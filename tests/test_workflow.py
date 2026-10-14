import sqlite3
import zipfile
from datetime import date
from io import BytesIO
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from app import config, database, storage
from app.backup import create_backup
from app.database import POSTGRES_SCHEMA, prepare_postgres_statement
from app.main import app, due_date_after_one_month
from app.security import decrypt_bytes, encrypt_text, hash_password, verify_password
from app.storage import read_document, save_encrypted_document
from app.manage import reset_password


PERSON_PNG = b"\x89PNG\r\n\x1a\n" + b"test-person-image-payload"
AADHAAR_PNG = b"\x89PNG\r\n\x1a\n" + b"test-aadhaar-image-payload"
ADMIN_PASSWORD = "test-only-strong-password"


@pytest.fixture(autouse=True)
def isolate_tests_from_production(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DATABASE_URL", "")
    monkeypatch.setattr(config, "BLOB_READ_WRITE_TOKEN", "")
    monkeypatch.setenv("HOSTEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))


@pytest.fixture
def logged_in_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "DATABASE_PATH", data_dir / "hostel.sqlite3")
    monkeypatch.setattr(config, "DOCUMENTS_DIR", data_dir / "documents")
    monkeypatch.setattr(config, "BACKUPS_DIR", data_dir / "backups")
    monkeypatch.setattr(config, "COOKIE_SECURE", False)
    monkeypatch.setenv("HOSTEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))

    with TestClient(app) as client:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO staff (id, owner_id, username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("admin-id", "admin-id", "admin", hash_password(ADMIN_PASSWORD), "admin", "2026-01-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO hostels (id, owner_id, name, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                ("test-hostel", "admin-id", "Test Hostel", "admin-id", "2026-01-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO floors (id, hostel_id, floor_number, created_at) VALUES (?, ?, ?, ?)",
                ("test-floor-1", "test-hostel", 1, "2026-01-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO rooms (id, floor_id, room_number, share_count, created_at) VALUES (?, ?, ?, ?, ?)",
                ("room-101", "test-floor-1", "101", 4, "2026-01-01T00:00:00+00:00"),
            )
        response = client.post("/api/session", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert response.status_code == 200
        yield client, response.json()["csrf_token"]


def resident_form(**overrides: str) -> dict[str, str]:
    form = {
        "name": "Asha Resident",
        "mobile": "+919876543210",
        "aadhaar": "123456789012",
        "room": "room-101",
        "bed_number": "2",
        "joining_date": "2026-01-31",
        "payment_status": "unpaid",
        "amount_due": "1250.50",
    }
    form.update(overrides)
    return form


def test_private_blob_download_uses_read_write_token(monkeypatch: pytest.MonkeyPatch):
    key = Fernet.generate_key()
    monkeypatch.setenv("HOSTEL_ENCRYPTION_KEY", key.decode("ascii"))
    monkeypatch.setattr(config, "BLOB_READ_WRITE_TOKEN", "test-blob-token")
    encrypted_contents = Fernet(key).encrypt(PERSON_PNG)
    request_details: dict[str, object] = {}

    class BlobResponse:
        content = encrypted_contents

        def raise_for_status(self) -> None:
            return None

    def fake_get(url: str, headers: dict[str, str], timeout: int) -> BlobResponse:
        request_details.update({"url": url, "headers": headers, "timeout": timeout})
        return BlobResponse()

    monkeypatch.setattr(storage.httpx, "get", fake_get)

    assert storage.read_document("https://private.blob.vercel-storage.com/secure-file.enc") == PERSON_PNG
    assert request_details["headers"] == {"Authorization": "Bearer test-blob-token", "x-api-version": "7"}


def test_vercel_function_route_serves_frontend_shell():
    with TestClient(app) as client:
        response = client.get("/api/index")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Haven Hostel" in response.text


def test_full_checkin_payment_checkout_and_encrypted_backup(logged_in_client, tmp_path: Path):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}

    assert client.get("/api/dashboard").status_code == 200
    assert client.post("/api/session/logout").status_code == 403
    assert client.post(
        "/api/residents",
        data=resident_form(),
        files={
            "person_photo": ("person.png", PERSON_PNG, "image/png"),
            "aadhaar_photo": ("aadhaar.png", AADHAAR_PNG, "image/png"),
        },
        headers=headers,
    ).status_code == 201

    dashboard = client.get("/api/dashboard").json()
    resident = dashboard["residents"][0]
    assert resident["room"] == "101"
    assert resident["hostel_name"] == "Test Hostel"
    assert resident["bed_number"] == 2
    assert resident["payment_due_date"] == "2026-02-28"
    assert resident["aadhaar_last4"] == "9012"
    assert dashboard["summary"]["capacity"] == 4
    assert dashboard["summary"]["available"] == 3
    assert dashboard["summary"]["outstanding_paise"] == 125050
    assert [document["kind"] for document in resident["documents"]] == ["person_photo", "aadhaar_photo"]

    conflict = client.post("/api/residents", data=resident_form(aadhaar="", payment_status="paid", amount_due=""), headers=headers)
    assert conflict.status_code == 409

    for document in resident["documents"]:
        download = client.get(document["url"])
        expected = PERSON_PNG if document["kind"] == "person_photo" else AADHAAR_PNG
        assert download.status_code == 200
        assert download.content == expected
        encrypted_path = next(config.DOCUMENTS_DIR.glob("*.enc"))
        assert encrypted_path.read_bytes() != expected

    paid = client.post(f"/api/residents/{resident['id']}/payment", headers=headers)
    assert paid.status_code == 200
    assert client.get("/api/dashboard").json()["summary"]["outstanding_paise"] == 0

    checkout = client.delete(f"/api/residents/{resident['id']}", headers=headers)
    assert checkout.status_code == 200
    after_checkout = client.get("/api/dashboard").json()
    assert after_checkout["summary"]["occupied"] == 0
    assert after_checkout["summary"]["available"] == 4
    assert next(room for room in after_checkout["rooms"] if room["id"] == "room-101")["beds"][1]["occupied"] is False

    audit = client.get("/api/audit").json()
    actions = {event["action"] for event in audit}
    assert {"resident.checkin", "payment.mark_paid", "resident.checkout", "document.download"} <= actions
    assert "123456789012" not in str(audit)

    with database.read_connection() as connection:
        database_bytes = config.DATABASE_PATH.read_bytes()
        stored_identifiers = connection.execute(
            "SELECT name_ciphertext, mobile_ciphertext, aadhaar_ciphertext FROM residents"
        ).fetchone()
    assert b"Asha Resident" not in database_bytes
    assert b"9876543210" not in database_bytes
    assert b"123456789012" not in database_bytes
    assert stored_identifiers["aadhaar_ciphertext"]

    backup_path = create_backup()
    encrypted_backup = backup_path.read_bytes()
    assert b"Asha Resident" not in encrypted_backup
    with zipfile.ZipFile(BytesIO(decrypt_bytes(encrypted_backup))) as archive:
        assert "hostel.sqlite3" in archive.namelist()
        assert len([name for name in archive.namelist() if name.startswith("documents/")]) == 2
        assert b"123456789012" not in archive.read("hostel.sqlite3")


def test_staff_roles_and_csrf_are_enforced(logged_in_client):
    client, csrf = logged_in_client
    admin_headers = {"X-CSRF-Token": csrf}
    created = client.post(
        "/api/staff",
        json={"username": "warden1", "password": "another-strong-password", "role": "warden"},
        headers=admin_headers,
    )
    assert created.status_code == 201

    client.cookies.clear()
    login = client.post("/api/session", json={"username": "warden1", "password": "another-strong-password"})
    assert login.status_code == 200
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/audit").status_code == 403
    assert client.get("/api/staff").status_code == 403
    assert client.post(
        "/api/staff",
        json={"username": "warden2", "password": "another-strong-password", "role": "warden"},
        headers={"X-CSRF-Token": login.json()["csrf_token"]},
    ).status_code == 403


def test_cli_password_reset_updates_hash_and_revokes_sessions(logged_in_client, monkeypatch: pytest.MonkeyPatch):
    client, _ = logged_in_client
    new_password = "updated-owner-password"
    passwords = iter((new_password, new_password))
    monkeypatch.setattr("app.manage.getpass.getpass", lambda _: next(passwords))

    reset_password("admin")

    assert client.get("/api/dashboard").status_code == 401
    with database.read_connection() as connection:
        password_hash = connection.execute("SELECT password_hash FROM staff WHERE username = ?", ("admin",)).fetchone()[0]
        session_count = connection.execute("SELECT COUNT(*) FROM sessions WHERE staff_id = ?", ("admin-id",)).fetchone()[0]
    assert verify_password(password_hash, new_password)
    assert session_count == 0


def test_owner_data_is_isolated_from_other_admins(logged_in_client):
    owner_client, owner_csrf = logged_in_client
    created_resident = owner_client.post(
        "/api/residents",
        data=resident_form(payment_status="paid", amount_due=""),
        files={"person_photo": ("person.png", PERSON_PNG, "image/png")},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert created_resident.status_code == 201
    resident_id = created_resident.json()["id"]
    dashboard = owner_client.get("/api/dashboard").json()
    document_id = dashboard["residents"][0]["documents"][0]["url"].rsplit("/", 1)[-1]

    created_owner = owner_client.post(
        "/api/staff",
        json={"username": "second-owner", "password": "second-owner-password", "role": "admin"},
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert created_owner.status_code == 201

    with TestClient(app) as other_owner_client:
        login = other_owner_client.post(
            "/api/session", json={"username": "second-owner", "password": "second-owner-password"}
        )
        assert login.status_code == 200
        other_csrf = login.json()["csrf_token"]
        other_dashboard = other_owner_client.get("/api/dashboard").json()

        assert other_dashboard["hostels"] == []
        assert other_dashboard["rooms"] == []
        assert other_dashboard["residents"] == []
        assert other_dashboard["activity"] == []
        assert [item["username"] for item in other_owner_client.get("/api/staff").json()] == ["second-owner"]
        assert other_owner_client.post(
            f"/api/residents/{resident_id}/payment", headers={"X-CSRF-Token": other_csrf}
        ).status_code == 404
        assert other_owner_client.delete(
            f"/api/residents/{resident_id}", headers={"X-CSRF-Token": other_csrf}
        ).status_code == 404
        assert other_owner_client.get(f"/api/documents/{document_id}").status_code == 404
        assert other_owner_client.delete(
            "/api/hostels/test-hostel", headers={"X-CSRF-Token": other_csrf}
        ).status_code == 404

    assert owner_client.get("/api/dashboard").json()["residents"][0]["id"] == resident_id


def test_multiple_hostels_floors_rooms_and_sharing_are_flexible(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}

    hostel = client.post("/api/hostels", json={"name": "West Campus"}, headers=headers)
    assert hostel.status_code == 201
    hostel_id = hostel.json()["id"]
    first_floor = client.post(f"/api/hostels/{hostel_id}/floors", json={"floor_number": 1}, headers=headers)
    second_floor = client.post(f"/api/hostels/{hostel_id}/floors", json={"floor_number": 2}, headers=headers)
    assert first_floor.status_code == 201
    assert second_floor.status_code == 201
    empty_floors = client.get("/api/dashboard").json()
    north_campus = next(item for item in empty_floors["hostels"] if item["id"] == hostel_id)
    assert [floor["rooms"] for floor in north_campus["floors"]] == [[], []]

    for room_number in range(101, 106):
        created = client.post(
            f"/api/floors/{first_floor.json()['id']}/rooms",
            json={"room_number": str(room_number), "share_count": 4},
            headers=headers,
        )
        assert created.status_code == 201
    for room_number in range(201, 205):
        created = client.post(
            f"/api/floors/{second_floor.json()['id']}/rooms",
            json={"room_number": str(room_number), "share_count": 6 if room_number == 201 else 3},
            headers=headers,
        )
        assert created.status_code == 201

    structure = client.get("/api/dashboard").json()
    west_campus = next(item for item in structure["hostels"] if item["id"] == hostel_id)
    assert [len(floor["rooms"]) for floor in west_campus["floors"]] == [5, 4]
    assert structure["summary"]["capacity"] == 39

    resident = client.post(
        "/api/residents",
        data=resident_form(
            name="Sixth Bed Resident",
            aadhaar="",
            room=next(room["id"] for room in structure["rooms"] if room["room_number"] == "201"),
            bed_number="6",
            payment_status="paid",
            amount_due="",
        ),
        headers=headers,
    )
    assert resident.status_code == 201
    updated = client.get("/api/dashboard").json()
    room_201 = next(room for room in updated["rooms"] if room["room_number"] == "201")
    assert len(room_201["beds"]) == 6
    assert room_201["beds"][5]["occupied"] is True


def test_vercel_defaults_use_tmp_data_dir(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.delenv("HOSTEL_DATA_DIR", raising=False)
    import importlib

    import app.config as config_module

    reloaded = importlib.reload(config_module)
    assert reloaded.DATA_DIR.name == "hostel-data"
    assert "Hostel\\data" not in str(reloaded.DATA_DIR)
    assert reloaded.DATABASE_PATH == reloaded.DATA_DIR / "hostel.sqlite3"


def test_room_delete_requires_vacancy_and_retains_resident_history(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}
    created = client.post("/api/residents", data=resident_form(payment_status="paid", amount_due=""), headers=headers)
    assert created.status_code == 201
    resident_id = created.json()["id"]

    occupied_delete = client.delete("/api/rooms/room-101", headers=headers)
    assert occupied_delete.status_code == 409

    assert client.delete(f"/api/residents/{resident_id}", headers=headers).status_code == 200
    deleted = client.delete("/api/rooms/room-101", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"status": "deleted", "room_number": "101"}

    dashboard = client.get("/api/dashboard").json()
    assert dashboard["rooms"] == []
    assert dashboard["summary"]["capacity"] == 0
    with database.read_connection() as connection:
        room = connection.execute("SELECT active FROM rooms WHERE id = ?", ("room-101",)).fetchone()
        historical_resident = connection.execute("SELECT checked_out_at FROM residents WHERE id = ?", (resident_id,)).fetchone()
    assert room["active"] == 0
    assert historical_resident["checked_out_at"] is not None
    assert any(event["action"] == "room.delete" for event in client.get("/api/audit").json())


def test_hostel_delete_requires_vacancy_and_archives_all_rooms(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}
    hostel = client.post("/api/hostels", json={"name": "Archive Test Hostel"}, headers=headers)
    assert hostel.status_code == 201
    hostel_id = hostel.json()["id"]
    floor = client.post(f"/api/hostels/{hostel_id}/floors", json={"floor_number": 1}, headers=headers)
    room = client.post(
        f"/api/floors/{floor.json()['id']}/rooms",
        json={"room_number": "601", "share_count": 6},
        headers=headers,
    )
    resident = client.post(
        "/api/residents",
        data=resident_form(
            name="Hostel History Resident",
            aadhaar="",
            room=room.json()["id"],
            bed_number="6",
            payment_status="paid",
            amount_due="",
        ),
        headers=headers,
    )
    resident_id = resident.json()["id"]

    occupied_delete = client.delete(f"/api/hostels/{hostel_id}", headers=headers)
    assert occupied_delete.status_code == 409

    assert client.delete(f"/api/residents/{resident_id}", headers=headers).status_code == 200
    deleted = client.delete(f"/api/hostels/{hostel_id}", headers=headers)
    assert deleted.status_code == 200
    dashboard = client.get("/api/dashboard").json()
    assert hostel_id not in {item["id"] for item in dashboard["hostels"]}
    assert room.json()["id"] not in {item["id"] for item in dashboard["rooms"]}
    with database.read_connection() as connection:
        archived = connection.execute("SELECT active FROM hostels WHERE id = ?", (hostel_id,)).fetchone()
        archived_room = connection.execute("SELECT active FROM rooms WHERE id = ?", (room.json()["id"],)).fetchone()
        history = connection.execute("SELECT checked_out_at FROM residents WHERE id = ?", (resident_id,)).fetchone()
    assert archived["active"] == 0
    assert archived_room["active"] == 0
    assert history["checked_out_at"] is not None
    assert any(event["action"] == "hostel.delete" for event in client.get("/api/audit").json())


def test_fixed_room_database_migrates_without_losing_residents(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "legacy-data"
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "DATABASE_PATH", data_dir / "hostel.sqlite3")
    monkeypatch.setattr(config, "DOCUMENTS_DIR", data_dir / "documents")
    monkeypatch.setattr(config, "BACKUPS_DIR", data_dir / "backups")
    monkeypatch.setenv("HOSTEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))
    data_dir.mkdir(parents=True)

    with sqlite3.connect(config.DATABASE_PATH) as connection:
        connection.execute(
            "CREATE TABLE staff (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, "
            "role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE residents (id TEXT PRIMARY KEY, name_ciphertext TEXT NOT NULL, "
            "mobile_ciphertext TEXT NOT NULL, aadhaar_ciphertext TEXT, room_id TEXT NOT NULL, "
            "bed_number INTEGER NOT NULL CHECK (bed_number BETWEEN 1 AND 4), joining_date TEXT NOT NULL, "
            "payment_due_date TEXT NOT NULL, payment_status TEXT NOT NULL, amount_due_paise INTEGER NOT NULL, "
            "created_by TEXT NOT NULL REFERENCES staff(id), created_at TEXT NOT NULL, checked_out_at TEXT)"
        )
        connection.execute(
            "INSERT INTO staff (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("legacy-admin", "legacy-admin", hash_password("legacy-test-password"), "admin", "2026-01-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO residents (id, name_ciphertext, mobile_ciphertext, room_id, bed_number, joining_date, "
            "payment_due_date, payment_status, amount_due_paise, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "legacy-resident",
                encrypt_text("Legacy Resident"),
                encrypt_text("9876543210"),
                "101",
                1,
                "2026-01-31",
                "2026-02-28",
                "paid",
                0,
                "legacy-admin",
                "2026-01-31T00:00:00Z",
            ),
        )

    database.initialize_database()
    with database.read_connection() as connection:
        owner = connection.execute("SELECT owner_id FROM staff WHERE id = ?", ("legacy-admin",)).fetchone()
        hostel_owner = connection.execute("SELECT owner_id FROM hostels WHERE id = ?", ("legacy-hostel",)).fetchone()
        resident = connection.execute("SELECT room_id, bed_number FROM residents WHERE id = ?", ("legacy-resident",)).fetchone()
        room = connection.execute("SELECT share_count FROM rooms WHERE id = ?", ("101",)).fetchone()
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        bed_constraint = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'residents'"
        ).fetchone()[0]

    assert resident["room_id"] == "101"
    assert resident["bed_number"] == 1
    assert owner["owner_id"] == "legacy-admin"
    assert hostel_owner["owner_id"] == "legacy-admin"
    assert room["share_count"] == 4
    assert not foreign_key_errors
    assert "BETWEEN 1 AND 20" in bed_constraint


def test_existing_flexible_rooms_get_active_flag_migration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "room-active-data"
    data_dir.mkdir(parents=True)
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "DATABASE_PATH", data_dir / "hostel.sqlite3")
    monkeypatch.setattr(config, "DOCUMENTS_DIR", data_dir / "documents")
    monkeypatch.setattr(config, "BACKUPS_DIR", data_dir / "backups")
    monkeypatch.setenv("HOSTEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))

    with sqlite3.connect(config.DATABASE_PATH) as connection:
        connection.executescript(
            "CREATE TABLE staff (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, "
            "role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);"
            "CREATE TABLE hostels (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_by TEXT NOT NULL, created_at TEXT NOT NULL);"
            "CREATE TABLE floors (id TEXT PRIMARY KEY, hostel_id TEXT NOT NULL, floor_number INTEGER NOT NULL, created_at TEXT NOT NULL);"
            "CREATE TABLE rooms (id TEXT PRIMARY KEY, floor_id TEXT NOT NULL, room_number TEXT NOT NULL, "
            "share_count INTEGER NOT NULL, created_at TEXT NOT NULL, UNIQUE (floor_id, room_number));"
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
            "INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2026-01-01T00:00:00Z');"
        )
        connection.execute(
            "INSERT INTO staff (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            ("schema-admin", "schema-admin", hash_password("schema-test-password"), "admin", "2026-01-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO hostels (id, name, created_by, created_at) VALUES (?, ?, ?, ?)",
            ("schema-hostel", "Schema Hostel", "schema-admin", "2026-01-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO floors (id, hostel_id, floor_number, created_at) VALUES (?, ?, ?, ?)",
            ("schema-floor", "schema-hostel", 1, "2026-01-01T00:00:00Z"),
        )
        connection.execute(
            "INSERT INTO rooms (id, floor_id, room_number, share_count, created_at) VALUES (?, ?, ?, ?, ?)",
            ("schema-room", "schema-floor", "11", 6, "2026-01-01T00:00:00Z"),
        )

    database.initialize_database()
    with database.read_connection() as connection:
        room = connection.execute("SELECT active, share_count FROM rooms WHERE id = ?", ("schema-room",)).fetchone()
        hostel = connection.execute("SELECT active FROM hostels WHERE id = ?", ("schema-hostel",)).fetchone()
        version = connection.execute("SELECT 1 FROM schema_migrations WHERE version = 2").fetchone()

    assert room["active"] == 1
    assert room["share_count"] == 6
    assert hostel["active"] == 1
    assert version is not None


def test_first_admin_signup_is_local_only_and_single_use(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "first-admin-data"
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "DATABASE_PATH", data_dir / "hostel.sqlite3")
    monkeypatch.setattr(config, "DOCUMENTS_DIR", data_dir / "documents")
    monkeypatch.setattr(config, "BACKUPS_DIR", data_dir / "backups")
    monkeypatch.setattr(config, "COOKIE_SECURE", False)
    monkeypatch.setenv("HOSTEL_ENCRYPTION_KEY", Fernet.generate_key().decode("ascii"))

    with TestClient(app, client=("203.0.113.20", 5000)) as remote_client:
        assert remote_client.get("/api/setup-status").json() == {"setup_required": False}
        remote_signup = remote_client.post(
            "/api/setup-admin",
            json={"username": "first-admin", "password": "first-admin-test-password"},
        )
        assert remote_signup.status_code == 403

    with TestClient(app, client=("127.0.0.1", 5000)) as local_client:
        assert local_client.get("/api/setup-status").json() == {"setup_required": True}
        signup = local_client.post(
            "/api/setup-admin",
            json={"username": "first-admin", "password": "first-admin-test-password"},
        )
        assert signup.status_code == 201
        assert signup.json()["user"] == {"username": "first-admin", "role": "admin"}
        assert local_client.get("/api/session").json()["user"]["username"] == "first-admin"
        assert local_client.get("/api/setup-status").json() == {"setup_required": False}
        second_signup = local_client.post(
            "/api/setup-admin",
            json={"username": "second-admin", "password": "second-admin-test-password"},
        )
        assert second_signup.status_code == 409


@pytest.mark.parametrize(
    ("joining", "expected"),
    [
        (date(2026, 1, 31), date(2026, 2, 28)),
        (date(2024, 1, 31), date(2024, 2, 29)),
        (date(2026, 5, 31), date(2026, 6, 30)),
        (date(2026, 12, 31), date(2027, 1, 31)),
    ],
)
def test_monthly_payment_date_clamps_to_month_end(joining: date, expected: date):
    assert due_date_after_one_month(joining) == expected


def test_postgres_schema_and_placeholders_are_serverless_compatible():
    assert "BIGSERIAL PRIMARY KEY" in POSTGRES_SCHEMA
    assert "AUTOINCREMENT" not in POSTGRES_SCHEMA
    assert "COLLATE NOCASE" not in POSTGRES_SCHEMA
    assert prepare_postgres_statement("SELECT id FROM residents WHERE room_id = ? AND bed_number = ?") == (
        "SELECT id FROM residents WHERE room_id = %s AND bed_number = %s"
    )
    assert prepare_postgres_statement("INSERT OR IGNORE INTO rooms (id) VALUES (?)").endswith(
        "VALUES (%s) ON CONFLICT DO NOTHING"
    )


def test_vercel_blob_upload_stores_only_encrypted_document_bytes(monkeypatch: pytest.MonkeyPatch):
    plaintext = b"private-resident-document-content"
    uploaded: dict[str, object] = {}
    monkeypatch.setattr(config, "BLOB_READ_WRITE_TOKEN", "test-only-token")

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"url": "https://test-store.public.blob.vercel-storage.com/resident-documents/test.enc"}

    def fake_put(url, content, headers, timeout):
        uploaded.update({"url": url, "content": content, "headers": headers})
        return FakeResponse()

    def fake_get(url, headers, timeout):
        assert headers["Authorization"] == "Bearer test-only-token"
        class DownloadResponse:
            content = uploaded["content"]

            def raise_for_status(self):
                return None

        return DownloadResponse()

    monkeypatch.setattr("app.storage.httpx.put", fake_put)
    monkeypatch.setattr("app.storage.httpx.get", fake_get)

    location = save_encrypted_document(plaintext)
    assert location == "https://test-store.public.blob.vercel-storage.com/resident-documents/test.enc"
    assert uploaded["content"] != plaintext
    assert decrypt_bytes(uploaded["content"]) == plaintext
    assert uploaded["headers"]["Authorization"] == "Bearer test-only-token"
    assert read_document(location) == plaintext