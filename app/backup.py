import os
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import json

from app import config, database
from app.security import encrypt_bytes
from app.storage import put_encrypted_blob, read_encrypted_object


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
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(database_copy, "hostel.sqlite3")
            for document in config.DOCUMENTS_DIR.glob("*.enc"):
                archive.write(document, f"documents/{document.name}")

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_path = config.BACKUPS_DIR / f"hostel-{timestamp}.backup"
        with backup_path.open("xb") as backup_file:
            backup_file.write(encrypt_bytes(archive_path.read_bytes()))
        try:
            os.chmod(backup_path, 0o600)
        except OSError:
            pass

    backups = sorted(config.BACKUPS_DIR.glob("hostel-*.backup"), key=lambda path: path.stat().st_mtime, reverse=True)
    for old_backup in backups[config.MAX_BACKUPS :]:
        old_backup.unlink(missing_ok=True)
    return backup_path


def create_postgres_backup() -> str:
    tables = (
        "staff",
        "hostels",
        "floors",
        "rooms",
        "residents",
        "documents",
        "audit_log",
        "login_attempts",
        "schema_migrations",
    )
    with database.transaction() as connection:
        database.write_audit(connection, None, "backup.created", "backup")

    snapshot: dict[str, list[dict[str, object]]] = {}
    with database.read_connection() as connection:
        for table in tables:
            rows = connection.execute(f"SELECT * FROM {table}").fetchall()
            snapshot[table] = [dict(row) for row in rows]

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    archive_buffer = BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("database.json", json.dumps(snapshot, separators=(",", ":"), default=str))
        for document in snapshot["documents"]:
            encrypted_contents = read_encrypted_object(str(document["encrypted_path"]))
            archive.writestr(f"documents/{document['id']}.enc", encrypted_contents)

    encrypted_archive = encrypt_bytes(archive_buffer.getvalue())
    return put_encrypted_blob(f"hostel-backups/hostel-{timestamp}.backup", encrypted_archive)


def main() -> None:
    path = create_backup()
    print(f"Encrypted backup created: {path}")


if __name__ == "__main__":
    main()