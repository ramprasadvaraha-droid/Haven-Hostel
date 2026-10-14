import sqlite3
from pathlib import Path

from app import config, database
from app.storage import put_encrypted_blob


TABLES = (
    "staff",
    "hostels",
    "floors",
    "rooms",
    "residents",
    "documents",
    "audit_log",
    "login_attempts",
)


def migrate() -> dict[str, int]:
    if not config.DATABASE_URL:
        raise RuntimeError("Set DATABASE_URL to the Neon Postgres connection string before migrating.")
    if not config.BLOB_READ_WRITE_TOKEN:
        raise RuntimeError("Set BLOB_READ_WRITE_TOKEN before migrating encrypted documents.")
    if not config.DATABASE_PATH.is_file():
        raise RuntimeError(f"Local SQLite database not found at {config.DATABASE_PATH}.")

    database.initialize_database()
    with database.read_connection() as destination:
        existing = {
            table: destination.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("staff", "hostels", "residents")
        }
    if any(existing.values()):
        raise RuntimeError("The Neon database is not empty. Migration stopped without changing either database.")

    source = sqlite3.connect(config.DATABASE_PATH)
    source.row_factory = sqlite3.Row
    try:
        source_tables = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required_tables = set(TABLES) | {"schema_migrations"}
        if not required_tables.issubset(source_tables):
            raise RuntimeError("The local database schema is incomplete; start the local app once to run migrations.")
        room_columns = {row[1] for row in source.execute("PRAGMA table_info(rooms)")}
        hostel_columns = {row[1] for row in source.execute("PRAGMA table_info(hostels)")}
        if "active" not in room_columns or "active" not in hostel_columns:
            raise RuntimeError("Run the latest local app migration before transferring data to Neon.")

        source_documents = source.execute(
            "SELECT id, encrypted_path FROM documents ORDER BY id"
        ).fetchall()
        migrated_document_paths: dict[str, str] = {}
        for document in source_documents:
            original_path = str(document["encrypted_path"])
            filename = Path(original_path)
            if filename.name != original_path or filename.suffix != ".enc":
                raise RuntimeError("A local document path is invalid; migration stopped before importing records.")
            document_path = config.DOCUMENTS_DIR / filename
            if not document_path.is_file() or document_path.parent != config.DOCUMENTS_DIR:
                raise RuntimeError("An encrypted document is missing; migration stopped before importing records.")
            blob_path = f"resident-documents/migrated-{document['id']}.enc"
            migrated_document_paths[document["id"]] = put_encrypted_blob(blob_path, document_path.read_bytes())

        row_counts: dict[str, int] = {}
        with database.transaction() as destination:
            for table in TABLES:
                columns = [row[1] for row in source.execute(f"PRAGMA table_info({table})").fetchall()]
                placeholders = ", ".join("?" for _ in columns)
                column_list = ", ".join(columns)
                rows = source.execute(f"SELECT {column_list} FROM {table}").fetchall()
                for row in rows:
                    values = [row[column] for column in columns]
                    if table == "documents":
                        path_index = columns.index("encrypted_path")
                        values[path_index] = migrated_document_paths[row["id"]]
                    destination.execute(
                        f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})",
                        values,
                    )
                row_counts[table] = len(rows)

            max_audit_id = destination.execute("SELECT COALESCE(MAX(id), 0) FROM audit_log").fetchone()[0]
            if max_audit_id:
                destination.execute(
                    "SELECT setval(pg_get_serial_sequence('audit_log', 'id'), ?, true)",
                    (max_audit_id,),
                )
        return row_counts
    finally:
        source.close()


def main() -> None:
    imported = migrate()
    print("Migration complete. Imported row counts:")
    for table, count in imported.items():
        print(f"  {table}: {count}")
    print("Sessions were not transferred; staff must sign in again.")


if __name__ == "__main__":
    main()