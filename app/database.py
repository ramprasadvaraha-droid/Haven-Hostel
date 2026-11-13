import json
import os
import re
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from app import config


SCHEMA = """
CREATE TABLE IF NOT EXISTS staff (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES staff(id),
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'warden')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    staff_id TEXT NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS platform_accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    recovery_email TEXT,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS platform_sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES platform_accounts(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS platform_password_resets (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES platform_accounts(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS platform_password_reset_account ON platform_password_resets(account_id, created_at DESC);
CREATE TABLE IF NOT EXISTS subscription_payments (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES staff(id),
    billing_period TEXT NOT NULL,
    amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
    due_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'received')),
    received_at TEXT,
    received_by TEXT REFERENCES platform_accounts(id),
    created_by TEXT NOT NULL REFERENCES platform_accounts(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (owner_id, billing_period)
);
CREATE INDEX IF NOT EXISTS subscription_status_due ON subscription_payments(status, due_date);
CREATE TABLE IF NOT EXISTS hostels (
    id TEXT PRIMARY KEY,
    owner_id TEXT REFERENCES staff(id),
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    ac_type TEXT NOT NULL DEFAULT 'mixed' CHECK (ac_type IN ('ac', 'mixed')),
    address_ciphertext TEXT,
    location_ciphertext TEXT,
    owner_mobile_ciphertext TEXT,
    created_by TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS floors (
    id TEXT PRIMARY KEY,
    hostel_id TEXT NOT NULL REFERENCES hostels(id) ON DELETE CASCADE,
    floor_number INTEGER NOT NULL CHECK (floor_number BETWEEN 1 AND 99),
    floor_type TEXT NOT NULL DEFAULT 'standard' CHECK (floor_type IN ('basement', 'ground', 'standard', 'penthouse')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    floor_id TEXT NOT NULL REFERENCES floors(id) ON DELETE CASCADE,
    room_number TEXT NOT NULL,
    share_count INTEGER NOT NULL CHECK (share_count BETWEEN 1 AND 20),
    ac_type TEXT NOT NULL DEFAULT 'non_ac' CHECK (ac_type IN ('ac', 'non_ac')),
    monthly_rent_paise INTEGER NOT NULL DEFAULT 0 CHECK (monthly_rent_paise >= 0),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL,
    UNIQUE (floor_id, room_number)
);
CREATE TABLE IF NOT EXISTS room_type_charges (
    hostel_id TEXT NOT NULL REFERENCES hostels(id) ON DELETE CASCADE,
    share_count INTEGER NOT NULL CHECK (share_count BETWEEN 1 AND 20),
    ac_type TEXT NOT NULL DEFAULT 'non_ac' CHECK (ac_type IN ('ac', 'non_ac')),
    monthly_rent_paise INTEGER NOT NULL CHECK (monthly_rent_paise >= 0),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (hostel_id, share_count, ac_type)
);
CREATE TABLE IF NOT EXISTS residents (
    id TEXT PRIMARY KEY,
    name_ciphertext TEXT NOT NULL,
    mobile_ciphertext TEXT NOT NULL,
    aadhaar_ciphertext TEXT,
    room_id TEXT NOT NULL REFERENCES rooms(id),
    bed_number INTEGER NOT NULL CHECK (bed_number BETWEEN 1 AND 20),
    joining_date TEXT NOT NULL,
    payment_due_date TEXT NOT NULL,
    payment_status TEXT NOT NULL CHECK (payment_status IN ('paid', 'unpaid')),
    amount_due_paise INTEGER NOT NULL DEFAULT 0 CHECK (amount_due_paise >= 0),
    whatsapp_opt_in INTEGER NOT NULL DEFAULT 0 CHECK (whatsapp_opt_in IN (0, 1)),
    created_by TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL,
    checked_out_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS active_bed_assignment
ON residents(room_id, bed_number) WHERE checked_out_at IS NULL;
CREATE TABLE IF NOT EXISTS registration_invites (
    id TEXT PRIMARY KEY,
    hostel_id TEXT NOT NULL REFERENCES hostels(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES staff(id),
    created_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS registration_invite_hostel
ON registration_invites(hostel_id, created_at DESC);
CREATE TABLE IF NOT EXISTS registration_applications (
    id TEXT PRIMARY KEY,
    invite_id TEXT NOT NULL UNIQUE REFERENCES registration_invites(id),
    hostel_id TEXT NOT NULL REFERENCES hostels(id),
    name_ciphertext TEXT NOT NULL,
    mobile_ciphertext TEXT NOT NULL,
    aadhaar_ciphertext TEXT,
    whatsapp_opt_in INTEGER NOT NULL DEFAULT 0 CHECK (whatsapp_opt_in IN (0, 1)),
    person_photo_path TEXT,
    person_photo_media_type TEXT,
    aadhaar_photo_path TEXT,
    aadhaar_photo_media_type TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved')),
    submitted_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewed_by TEXT REFERENCES staff(id),
    resident_id TEXT REFERENCES residents(id)
);
CREATE INDEX IF NOT EXISTS registration_application_hostel_status
ON registration_applications(hostel_id, status, submitted_at DESC);
CREATE TABLE IF NOT EXISTS bookings (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES staff(id),
    hostel_id TEXT NOT NULL REFERENCES hostels(id),
    student_name TEXT,
    phone TEXT NOT NULL,
    phone_hash TEXT NOT NULL,
    sharing_needed INTEGER CHECK (sharing_needed BETWEEN 1 AND 20),
    budget INTEGER CHECK (budget >= 0),
    status TEXT NOT NULL CHECK (status IN ('enquiry', 'visit_booked', 'joined')),
    visit_time TEXT,
    room_id_reserved TEXT REFERENCES rooms(id),
    reservation_expires_at TEXT,
    language TEXT NOT NULL DEFAULT 'en',
    cancelled_at TEXT,
    resident_id TEXT REFERENCES residents(id),
    created_by TEXT REFERENCES staff(id),
    confirmed_by TEXT REFERENCES staff(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS booking_owner_status ON bookings(owner_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS booking_room_reservation ON bookings(room_id_reserved, reservation_expires_at);
CREATE INDEX IF NOT EXISTS booking_phone_lookup ON bookings(phone_hash, hostel_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS active_room_reservation ON bookings(room_id_reserved)
WHERE status = 'visit_booked' AND cancelled_at IS NULL;
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    resident_id TEXT NOT NULL REFERENCES residents(id),
    kind TEXT NOT NULL CHECK (kind IN ('person_photo', 'aadhaar_photo')),
    encrypted_path TEXT NOT NULL UNIQUE,
    media_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (resident_id, kind)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    staff_id TEXT REFERENCES staff(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_at ON audit_log(created_at DESC);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    address_hash TEXT NOT NULL,
    succeeded INTEGER NOT NULL,
    attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempt_lookup
ON login_attempts(username, address_hash, attempted_at DESC);
CREATE INDEX IF NOT EXISTS platform_session_expiry ON platform_sessions(expires_at);
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""


POSTGRES_SCHEMA = (
    SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
    .replace(" COLLATE NOCASE", "")
    .replace(
        "floor_type TEXT NOT NULL DEFAULT 'standard' CHECK "
        "(floor_type IN ('basement', 'ground', 'standard', 'penthouse')),\n"
        "    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),\n"
        "    created_at TEXT NOT NULL\n);",
        "floor_type TEXT NOT NULL DEFAULT 'standard' CHECK "
        "(floor_type IN ('basement', 'ground', 'standard', 'penthouse')),\n"
        "    active BOOLEAN NOT NULL DEFAULT TRUE,\n"
        "    created_at TEXT NOT NULL\n);",
    )
)


def prepare_postgres_statement(statement: str) -> str:
    statement = statement.strip()
    if statement.upper().startswith("INSERT OR IGNORE INTO"):
        statement = re.sub(r"^INSERT OR IGNORE INTO", "INSERT INTO", statement, flags=re.IGNORECASE)
        statement = statement.rstrip(";") + " ON CONFLICT DO NOTHING"
    return statement.replace(" COLLATE NOCASE", "").replace("?", "%s")


class PostgresRow(dict[str, Any]):
    def __init__(self, columns: list[str], values: tuple[Any, ...]):
        super().__init__(zip(columns, values))
        self._values = values

    def __getitem__(self, key: str | int) -> Any:
        return self._values[key] if isinstance(key, int) else super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor: Any):
        self._cursor = cursor
        self._columns = [column.name for column in cursor.description] if cursor.description else []

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    def fetchone(self) -> PostgresRow | None:
        row = self._cursor.fetchone()
        return PostgresRow(self._columns, row) if row is not None else None

    def fetchall(self) -> list[PostgresRow]:
        return [PostgresRow(self._columns, row) for row in self._cursor.fetchall()]


class PostgresConnection:
    def __init__(self, database_url: str):
        import psycopg

        if database_url.startswith("postgres://"):
            database_url = "postgresql://" + database_url.removeprefix("postgres://")
        self._connection = psycopg.connect(database_url, autocommit=True)

    def execute(self, statement: str, parameters: Any = ()) -> PostgresCursor:
        import psycopg

        statement = prepare_postgres_statement(statement)
        try:
            return PostgresCursor(self._connection.execute(statement, tuple(parameters)))
        except psycopg.IntegrityError as error:
            raise sqlite3.IntegrityError(str(error)) from error

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self) -> None:
        self._connection.execute("COMMIT")

    def rollback(self) -> None:
        self._connection.execute("ROLLBACK")

    def close(self) -> None:
        self._connection.close()


def connect() -> sqlite3.Connection | PostgresConnection:
    if config.DATABASE_URL:
        return PostgresConnection(config.DATABASE_URL)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(config.DATABASE_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    try:
        os.chmod(config.DATA_DIR, 0o700)
        if config.DATABASE_PATH.exists():
            os.chmod(config.DATABASE_PATH, 0o600)
    except OSError:
        pass
    return connection


@contextmanager
def read_connection() -> Iterator[sqlite3.Connection | PostgresConnection]:
    with closing(connect()) as connection:
        yield connection


@contextmanager
def transaction() -> Iterator[sqlite3.Connection | PostgresConnection]:
    connection = connect()
    try:
        connection.execute("BEGIN" if config.DATABASE_URL else "BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    if config.DATABASE_URL:
        with read_connection() as connection:
            connection.executescript(POSTGRES_SCHEMA)
        with transaction() as connection:
            now = datetime.now(timezone.utc).isoformat()
            connection.execute("ALTER TABLE platform_accounts ADD COLUMN IF NOT EXISTS recovery_email TEXT")
            connection.execute("ALTER TABLE staff ADD COLUMN IF NOT EXISTS owner_id TEXT REFERENCES staff(id)")
            connection.execute("ALTER TABLE hostels ADD COLUMN IF NOT EXISTS owner_id TEXT REFERENCES staff(id)")
            connection.execute(
                "UPDATE staff SET owner_id = (SELECT id FROM staff WHERE role = 'admin' ORDER BY created_at LIMIT 1) "
                "WHERE owner_id IS NULL"
            )
            connection.execute(
                "UPDATE hostels SET owner_id = COALESCE((SELECT owner_id FROM staff WHERE staff.id = hostels.created_by), "
                "(SELECT id FROM staff WHERE role = 'admin' ORDER BY created_at LIMIT 1)) WHERE owner_id IS NULL"
            )
            connection.execute("CREATE INDEX IF NOT EXISTS staff_owner_id ON staff(owner_id)")
            connection.execute("CREATE INDEX IF NOT EXISTS hostels_owner_id ON hostels(owner_id)")
            connection.execute(
                "ALTER TABLE rooms ADD COLUMN IF NOT EXISTS monthly_rent_paise INTEGER NOT NULL DEFAULT 0"
            )
            connection.execute(
                "ALTER TABLE hostels ADD COLUMN IF NOT EXISTS ac_type TEXT NOT NULL DEFAULT 'mixed'"
            )
            connection.execute(
                "ALTER TABLE floors ADD COLUMN IF NOT EXISTS floor_type TEXT NOT NULL DEFAULT 'standard'"
            )
            connection.execute("ALTER TABLE hostels ADD COLUMN IF NOT EXISTS address_ciphertext TEXT")
            connection.execute("ALTER TABLE hostels ADD COLUMN IF NOT EXISTS location_ciphertext TEXT")
            connection.execute("ALTER TABLE hostels ADD COLUMN IF NOT EXISTS owner_mobile_ciphertext TEXT")
            connection.execute("ALTER TABLE floors ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE")
            connection.execute("ALTER TABLE floors DROP CONSTRAINT IF EXISTS floors_hostel_id_floor_number_key")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS active_floor_number "
                "ON floors(hostel_id, floor_number) "
                "WHERE CAST(active AS TEXT) IN ('1', 'true')"
            )
            migration_eleven = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 11"
            ).fetchone()
            if not migration_eleven:
                connection.execute(
                    "ALTER TABLE rooms ADD COLUMN IF NOT EXISTS ac_type TEXT NOT NULL DEFAULT 'non_ac' "
                    "CHECK (ac_type IN ('ac', 'non_ac'))"
                )
                connection.execute(
                    "UPDATE rooms SET ac_type = 'ac' FROM floors floor JOIN hostels hostel "
                    "ON hostel.id = floor.hostel_id WHERE rooms.floor_id = floor.id AND hostel.ac_type = 'ac'"
                )
                connection.execute(
                    "ALTER TABLE room_type_charges ADD COLUMN IF NOT EXISTS ac_type TEXT NOT NULL DEFAULT 'non_ac' "
                    "CHECK (ac_type IN ('ac', 'non_ac'))"
                )
                connection.execute(
                    "UPDATE room_type_charges SET ac_type = 'ac' FROM hostels hostel "
                    "WHERE hostel.id = room_type_charges.hostel_id AND hostel.ac_type = 'ac'"
                )
                connection.execute("ALTER TABLE room_type_charges DROP CONSTRAINT IF EXISTS room_type_charges_pkey")
                connection.execute(
                    "ALTER TABLE room_type_charges DROP CONSTRAINT IF EXISTS room_type_charges_share_count_check"
                )
                connection.execute(
                    "ALTER TABLE room_type_charges ADD CONSTRAINT room_type_charges_share_count_check "
                    "CHECK (share_count BETWEEN 1 AND 20)"
                )
                connection.execute(
                    "ALTER TABLE room_type_charges ADD CONSTRAINT room_type_charges_pkey "
                    "PRIMARY KEY (hostel_id, share_count, ac_type)"
                )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (11, ?) ON CONFLICT DO NOTHING",
                    (now,),
                )
            for version in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11):
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?) ON CONFLICT DO NOTHING",
                    (version, now),
                )
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (12, ?) ON CONFLICT DO NOTHING",
                (now,),
            )
            connection.execute(
                "ALTER TABLE residents ADD COLUMN IF NOT EXISTS whatsapp_opt_in INTEGER NOT NULL DEFAULT 0 "
                "CHECK (whatsapp_opt_in IN (0, 1))"
            )
            connection.execute(
                "ALTER TABLE registration_applications ADD COLUMN IF NOT EXISTS whatsapp_opt_in INTEGER NOT NULL DEFAULT 0 "
                "CHECK (whatsapp_opt_in IN (0, 1))"
            )
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (13, ?) ON CONFLICT DO NOTHING",
                (now,),
            )
        return
    with read_connection() as connection:
        existing_tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        legacy_resident_schema = None
        if "residents" in existing_tables:
            legacy_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'residents'"
            ).fetchone()
            legacy_resident_schema = legacy_row[0] if legacy_row else None
        connection.executescript(SCHEMA)
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        try:
            already_migrated = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 1"
            ).fetchone()
            if not already_migrated and "residents" in existing_tables:
                now = datetime.now(timezone.utc).isoformat()
                admin = connection.execute(
                    "SELECT id FROM staff WHERE role = 'admin' ORDER BY created_at LIMIT 1"
                ).fetchone()
                if not admin:
                    raise RuntimeError("Cannot migrate legacy rooms without an admin account.")
                if not connection.execute("SELECT 1 FROM hostels LIMIT 1").fetchone():
                    connection.execute(
                        "INSERT INTO hostels (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
                        ("legacy-hostel", "Hostel 1", admin[0], now),
                    )
                    connection.execute(
                        "INSERT INTO floors (id, hostel_id, floor_number, created_at) VALUES (?, ?, ?, ?)",
                        ("legacy-floor-1", "legacy-hostel", 1, now),
                    )
                    legacy_rooms = {str(number) for number in range(101, 109)}
                    legacy_rooms.update(
                        row[0] for row in connection.execute("SELECT DISTINCT room_id FROM residents").fetchall()
                    )
                    for room_number in sorted(legacy_rooms):
                        connection.execute(
                            "INSERT OR IGNORE INTO rooms (id, floor_id, room_number, share_count, created_at) "
                            "VALUES (?, ?, ?, 4, ?)",
                            (room_number, "legacy-floor-1", room_number, now),
                        )

                if legacy_resident_schema and "BETWEEN 1 AND 4" in legacy_resident_schema:
                    connection.execute("DROP INDEX IF EXISTS active_bed_assignment")
                    connection.execute(
                        "CREATE TABLE residents_migrated ("
                        "id TEXT PRIMARY KEY, name_ciphertext TEXT NOT NULL, mobile_ciphertext TEXT NOT NULL, "
                        "aadhaar_ciphertext TEXT, room_id TEXT NOT NULL REFERENCES rooms(id), "
                        "bed_number INTEGER NOT NULL CHECK (bed_number BETWEEN 1 AND 20), "
                        "joining_date TEXT NOT NULL, payment_due_date TEXT NOT NULL, "
                        "payment_status TEXT NOT NULL CHECK (payment_status IN ('paid', 'unpaid')), "
                        "amount_due_paise INTEGER NOT NULL DEFAULT 0 CHECK (amount_due_paise >= 0), "
                        "created_by TEXT NOT NULL REFERENCES staff(id), created_at TEXT NOT NULL, checked_out_at TEXT)"
                    )
                    connection.execute(
                        "INSERT INTO residents_migrated (id, name_ciphertext, mobile_ciphertext, aadhaar_ciphertext, "
                        "room_id, bed_number, joining_date, payment_due_date, payment_status, amount_due_paise, "
                        "created_by, created_at, checked_out_at) "
                        "SELECT id, name_ciphertext, mobile_ciphertext, aadhaar_ciphertext, room_id, bed_number, "
                        "joining_date, payment_due_date, payment_status, amount_due_paise, created_by, created_at, "
                        "checked_out_at FROM residents"
                    )
                    connection.execute("DROP TABLE residents")
                    connection.execute("ALTER TABLE residents_migrated RENAME TO residents")
                    connection.execute(
                        "CREATE UNIQUE INDEX active_bed_assignment ON residents(room_id, bed_number) "
                        "WHERE checked_out_at IS NULL"
                    )

            if not already_migrated:
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            room_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(rooms)").fetchall()
            }
            migration_two = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 2"
            ).fetchone()
            if not migration_two:
                if "active" not in room_columns:
                    connection.execute(
                        "ALTER TABLE rooms ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))"
                    )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            hostel_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(hostels)").fetchall()
            }
            migration_three = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 3"
            ).fetchone()
            if not migration_three:
                if "active" not in hostel_columns:
                    connection.execute(
                        "ALTER TABLE hostels ADD COLUMN active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))"
                    )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (3, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_four = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 4"
            ).fetchone()
            if not migration_four:
                staff_columns = {row[1] for row in connection.execute("PRAGMA table_info(staff)").fetchall()}
                hostel_columns = {row[1] for row in connection.execute("PRAGMA table_info(hostels)").fetchall()}
                if "owner_id" not in staff_columns:
                    connection.execute("ALTER TABLE staff ADD COLUMN owner_id TEXT REFERENCES staff(id)")
                if "owner_id" not in hostel_columns:
                    connection.execute("ALTER TABLE hostels ADD COLUMN owner_id TEXT REFERENCES staff(id)")
                default_owner = connection.execute(
                    "SELECT id FROM staff WHERE role = 'admin' ORDER BY created_at LIMIT 1"
                ).fetchone()
                if default_owner:
                    connection.execute("UPDATE staff SET owner_id = ? WHERE owner_id IS NULL", (default_owner[0],))
                    connection.execute(
                        "UPDATE hostels SET owner_id = ? WHERE owner_id IS NULL", (default_owner[0],)
                    )
                connection.execute("CREATE INDEX IF NOT EXISTS staff_owner_id ON staff(owner_id)")
                connection.execute("CREATE INDEX IF NOT EXISTS hostels_owner_id ON hostels(owner_id)")
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (4, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_five = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 5"
            ).fetchone()
            if not migration_five:
                if "monthly_rent_paise" not in room_columns:
                    connection.execute(
                        "ALTER TABLE rooms ADD COLUMN monthly_rent_paise INTEGER NOT NULL DEFAULT 0 "
                        "CHECK (monthly_rent_paise >= 0)"
                    )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (5, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_six = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 6"
            ).fetchone()
            if not migration_six:
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (6, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_seven = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 7"
            ).fetchone()
            if not migration_seven:
                platform_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(platform_accounts)").fetchall()
                }
                if "recovery_email" not in platform_columns:
                    connection.execute("ALTER TABLE platform_accounts ADD COLUMN recovery_email TEXT")
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (7, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_eight = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 8"
            ).fetchone()
            if not migration_eight:
                hostel_columns = {row[1] for row in connection.execute("PRAGMA table_info(hostels)").fetchall()}
                floor_columns = {row[1] for row in connection.execute("PRAGMA table_info(floors)").fetchall()}
                if "ac_type" not in hostel_columns:
                    connection.execute(
                        "ALTER TABLE hostels ADD COLUMN ac_type TEXT NOT NULL DEFAULT 'mixed' "
                        "CHECK (ac_type IN ('ac', 'mixed'))"
                    )
                if "floor_type" not in floor_columns:
                    connection.execute(
                        "ALTER TABLE floors ADD COLUMN floor_type TEXT NOT NULL DEFAULT 'standard' "
                        "CHECK (floor_type IN ('basement', 'ground', 'standard', 'penthouse'))"
                    )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (8, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_nine = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 9"
            ).fetchone()
            if not migration_nine:
                hostel_columns = {row[1] for row in connection.execute("PRAGMA table_info(hostels)").fetchall()}
                for column in ("address_ciphertext", "location_ciphertext", "owner_mobile_ciphertext"):
                    if column not in hostel_columns:
                        connection.execute(f"ALTER TABLE hostels ADD COLUMN {column} TEXT")
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (9, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_ten = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 10"
            ).fetchone()
            if not migration_ten:
                floor_columns = {row[1] for row in connection.execute("PRAGMA table_info(floors)").fetchall()}
                if "active" not in floor_columns:
                    connection.execute(
                        "CREATE TABLE floors_new ("
                        "id TEXT PRIMARY KEY, hostel_id TEXT NOT NULL REFERENCES hostels(id) ON DELETE CASCADE, "
                        "floor_number INTEGER NOT NULL CHECK (floor_number BETWEEN 1 AND 99), "
                        "floor_type TEXT NOT NULL DEFAULT 'standard' "
                        "CHECK (floor_type IN ('basement', 'ground', 'standard', 'penthouse')), "
                        "active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)), created_at TEXT NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO floors_new (id, hostel_id, floor_number, floor_type, active, created_at) "
                        "SELECT id, hostel_id, floor_number, floor_type, 1, created_at FROM floors"
                    )
                    connection.execute("DROP TABLE floors")
                    connection.execute("ALTER TABLE floors_new RENAME TO floors")
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS active_floor_number ON floors(hostel_id, floor_number) "
                    "WHERE CAST(active AS TEXT) IN ('1', 'true')"
                )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (10, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_eleven = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 11"
            ).fetchone()
            if not migration_eleven:
                room_columns = {row[1] for row in connection.execute("PRAGMA table_info(rooms)").fetchall()}
                if "ac_type" not in room_columns:
                    connection.execute(
                        "ALTER TABLE rooms ADD COLUMN ac_type TEXT NOT NULL DEFAULT 'non_ac' "
                        "CHECK (ac_type IN ('ac', 'non_ac'))"
                    )
                connection.execute(
                    "UPDATE rooms SET ac_type = 'ac' WHERE floor_id IN ("
                    "SELECT floor.id FROM floors floor JOIN hostels hostel ON hostel.id = floor.hostel_id "
                    "WHERE hostel.ac_type = 'ac')"
                )
                charge_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(room_type_charges)").fetchall()
                }
                if "ac_type" not in charge_columns:
                    connection.execute("DROP TABLE IF EXISTS room_type_charges_new")
                    connection.execute(
                        "CREATE TABLE room_type_charges_new ("
                        "hostel_id TEXT NOT NULL REFERENCES hostels(id) ON DELETE CASCADE, "
                        "share_count INTEGER NOT NULL CHECK (share_count BETWEEN 1 AND 20), "
                        "ac_type TEXT NOT NULL DEFAULT 'non_ac' CHECK (ac_type IN ('ac', 'non_ac')), "
                        "monthly_rent_paise INTEGER NOT NULL CHECK (monthly_rent_paise >= 0), "
                        "updated_at TEXT NOT NULL, PRIMARY KEY (hostel_id, share_count, ac_type))"
                    )
                    connection.execute(
                        "INSERT INTO room_type_charges_new "
                        "(hostel_id, share_count, ac_type, monthly_rent_paise, updated_at) "
                        "SELECT charge.hostel_id, charge.share_count, "
                        "CASE WHEN hostel.ac_type = 'ac' THEN 'ac' ELSE 'non_ac' END, "
                        "charge.monthly_rent_paise, charge.updated_at "
                        "FROM room_type_charges charge JOIN hostels hostel ON hostel.id = charge.hostel_id"
                    )
                    connection.execute("DROP TABLE room_type_charges")
                    connection.execute("ALTER TABLE room_type_charges_new RENAME TO room_type_charges")
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (11, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_twelve = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 12"
            ).fetchone()
            if not migration_twelve:
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (12, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            migration_thirteen = connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = 13"
            ).fetchone()
            if not migration_thirteen:
                resident_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(residents)").fetchall()
                }
                application_columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(registration_applications)").fetchall()
                }
                if "whatsapp_opt_in" not in resident_columns:
                    connection.execute(
                        "ALTER TABLE residents ADD COLUMN whatsapp_opt_in INTEGER NOT NULL DEFAULT 0 "
                        "CHECK (whatsapp_opt_in IN (0, 1))"
                    )
                if "whatsapp_opt_in" not in application_columns:
                    connection.execute(
                        "ALTER TABLE registration_applications ADD COLUMN whatsapp_opt_in INTEGER NOT NULL DEFAULT 0 "
                        "CHECK (whatsapp_opt_in IN (0, 1))"
                    )
                connection.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (13, ?)",
                    (datetime.now(timezone.utc).isoformat(),),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys = ON")


def write_audit(
    connection: sqlite3.Connection,
    staff_id: str | None,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    details: dict[str, object] | None = None,
) -> None:
    connection.execute(
        "INSERT INTO audit_log (staff_id, action, entity_type, entity_id, details_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            staff_id,
            action,
            entity_type,
            entity_id,
            json.dumps(details or {}, separators=(",", ":")),
            datetime.now(timezone.utc).isoformat(),
        ),
    )