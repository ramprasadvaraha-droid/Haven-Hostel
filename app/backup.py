import json
import os
import re
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from app import config, database
from app.security import decrypt_bytes, encrypt_bytes
from app.storage import put_encrypted_blob, read_encrypted_object


BACKUP_TABLES = tuple(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", database.SCHEMA))


def _verify_sqlite_database(contents: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="hostel-backup-verify-") as temporary_directory:
        database_path = Path(temporary_directory) / "hostel.sqlite3"
        database_path.write_bytes(contents)
        with closing(sqlite3.connect(database_path)) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
                )
            }
    if integrity != "ok":
        raise RuntimeError("SQLite backup failed its integrity check.")
    if not set(BACKUP_TABLES) <= tables:
        raise RuntimeError("SQLite backup is missing application tables.")


def _verify_encrypted_archive(
    encrypted_archive: bytes,
    expected_files: set[str],
    expected_tables: set[str] | None = None,
) -> None:
    archive_contents = decrypt_bytes(encrypted_archive)
    with zipfile.ZipFile(BytesIO(archive_contents)) as archive:
        corrupted_file = archive.testzip()
        if corrupted_file:
            raise RuntimeError(f"Backup integrity check failed for {corrupted_file}.")
        archive_files = set(archive.namelist())
        missing_files = expected_files - archive_files
        if missing_files:
            raise RuntimeError(f"Backup is missing required files: {', '.join(sorted(missing_files))}.")
        if "hostel.sqlite3" in archive_files:
            _verify_sqlite_database(archive.read("hostel.sqlite3"))
        if expected_tables is not None:
            snapshot = json.loads(archive.read("database.json"))
            if set(snapshot) != expected_tables:
                raise RuntimeError("Postgres backup does not contain every application table.")
            manifest = json.loads(archive.read("document-manifest.json"))
            document_files = expected_files - {"database.json", "document-manifest.json"}
            if set(manifest.values()) != document_files:
                raise RuntimeError("Postgres backup document manifest is incomplete.")


def create_backup() -> Path | str:
    if config.DATABASE_URL:
        return create_postgres_backup()
    config.BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    config.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    if not config.DATABASE_PATH.is_file():
        raise RuntimeError("Hostel database does not exist yet; start the app before creating a backup.")
    with database.transaction() as connection:
        database.write_audit(connection, None, "backup.created", "backup")

    with tempfile.TemporaryDirectory(prefix="hostel-backup-") as temporary_directory:
        temporary = Path(temporary_directory)
        database_copy = temporary / "hostel.sqlite3"
        source = database.connect()
        destination = sqlite3.connect(database_copy)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

        archive_path = temporary / "snapshot.zip"
        documents = sorted(config.DOCUMENTS_DIR.glob("*.enc"))
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(database_copy, "hostel.sqlite3")
            for document in documents:
                archive.write(document, f"documents/{document.name}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_path = config.BACKUPS_DIR / f"hostel-{timestamp}.backup"
        with backup_path.open("xb") as backup_file:
            backup_file.write(encrypt_bytes(archive_path.read_bytes()))
        expected_files = {"hostel.sqlite3", *(f"documents/{document.name}" for document in documents)}
        _verify_encrypted_archive(backup_path.read_bytes(), expected_files)
        try:
            os.chmod(backup_path, 0o600)
        except OSError:
            pass

    backups = sorted(config.BACKUPS_DIR.glob("hostel-*.backup"), key=lambda path: path.stat().st_mtime, reverse=True)
    for old_backup in backups[config.MAX_BACKUPS :]:
        old_backup.unlink(missing_ok=True)
    return backup_path


def create_postgres_backup() -> str:
    with database.transaction() as connection:
        database.write_audit(connection, None, "backup.created", "backup")

    snapshot: dict[str, list[dict[str, object]]] = {}
    with database.read_connection() as connection:
        for table in BACKUP_TABLES:
            rows = connection.execute(f"SELECT * FROM {table}").fetchall()
            snapshot[table] = [dict(row) for row in rows]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    archive_buffer = BytesIO()
    document_manifest: dict[str, str] = {}
    document_files: set[str] = set()
    with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("database.json", json.dumps(snapshot, separators=(",", ":"), default=str))
        for document in snapshot["documents"]:
            location = str(document["encrypted_path"])
            archive_path = f"documents/{document['id']}.enc"
            archive.writestr(archive_path, read_encrypted_object(location))
            document_manifest[location] = archive_path
            document_files.add(archive_path)
        for application in snapshot["registration_applications"]:
            for kind, column in (
                ("person_photo", "person_photo_path"),
                ("aadhaar_photo", "aadhaar_photo_path"),
            ):
                location = application[column]
                if location:
                    archive_path = f"registration-applications/{application['id']}/{kind}.enc"
                    archive.writestr(archive_path, read_encrypted_object(str(location)))
                    document_manifest[str(location)] = archive_path
                    document_files.add(archive_path)
        archive.writestr(
            "document-manifest.json",
            json.dumps(document_manifest, separators=(",", ":")),
        )

    encrypted_archive = encrypt_bytes(archive_buffer.getvalue())
    backup_url = put_encrypted_blob(f"hostel-backups/hostel-{timestamp}.backup", encrypted_archive)
    stored_archive = read_encrypted_object(backup_url)
    _verify_encrypted_archive(
        stored_archive,
        {"database.json", "document-manifest.json", *document_files},
        set(BACKUP_TABLES),
    )
    return backup_url


def main() -> None:
    path = create_backup()
    print(f"Encrypted backup created: {path}")


if __name__ == "__main__":
    main()