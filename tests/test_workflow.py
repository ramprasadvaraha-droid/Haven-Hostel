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
from app.security import decrypt_bytes, encrypt_text, hash_password, password_policy_error, verify_password
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


def login_platform(client: TestClient) -> str:
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO platform_accounts (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            ("platform-admin", "developer", hash_password("Developer-password1!"), "2026-01-01T00:00:00+00:00"),
        )
    login = client.post(
        "/api/platform/session",
        json={"username": "developer", "password": "Developer-password1!"},
    )
    assert login.status_code == 200
    return login.json()["csrf_token"]


def test_dashboard_returns_five_latest_checkins_and_checkouts(logged_in_client):
    client, _ = logged_in_client
    with database.transaction() as connection:
        for action, prefix in (("resident.checkin", "IN"), ("resident.checkout", "OUT")):
            for index in range(7):
                database.write_audit(
                    connection,
                    "admin-id",
                    action,
                    "resident",
                    f"{prefix}-{index}",
                    {"room_number": f"{prefix}-{index}", "hostel_name": "Test Hostel", "floor_number": 1},
                )

    activity = client.get("/api/dashboard").json()["activity"]
    checkins = [item for item in activity if item["type"] == "join"]
    checkouts = [item for item in activity if item["type"] == "exit"]

    assert [item["room"] for item in checkins] == [f"IN-{index}" for index in range(6, 1, -1)]
    assert [item["room"] for item in checkouts] == [f"OUT-{index}" for index in range(6, 1, -1)]


@pytest.mark.parametrize(
    "password",
    ["A1!abc", "lowercase1!", "UPPERCASE1!", "NoNumber!!", "NoSpecial1"],
)
def test_password_policy_requires_all_character_classes(password: str):
    assert password_policy_error(password) is not None


def test_password_policy_accepts_eight_character_mixed_password():
    assert password_policy_error("A1!bcdef") is None


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
        json={"username": "warden1", "password": "Another-strong-password1!", "role": "warden"},
        headers=admin_headers,
    )
    assert created.status_code == 201
    owner_creation = client.post(
        "/api/staff",
        json={"username": "owner2", "password": "Another-strong-password1!", "role": "admin"},
        headers=admin_headers,
    )
    assert owner_creation.status_code == 403

    client.cookies.clear()
    login = client.post("/api/session", json={"username": "warden1", "password": "Another-strong-password1!"})
    assert login.status_code == 200
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/audit").status_code == 403
    assert client.get("/api/staff").status_code == 403
    assert client.post(
        "/api/staff",
        json={"username": "warden2", "password": "Another-strong-password1!", "role": "warden"},
        headers={"X-CSRF-Token": login.json()["csrf_token"]},
    ).status_code == 403


@pytest.mark.parametrize(
    "password",
    ["A1!abc", "lowercase1!", "UPPERCASE1!", "NoNumber!!", "NoSpecial1"],
)
def test_staff_creation_rejects_passwords_missing_policy_requirements(logged_in_client, password: str):
    client, csrf = logged_in_client
    response = client.post(
        "/api/staff",
        json={"username": "policy-user", "password": password, "role": "warden"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 422


def test_staff_creation_accepts_eight_character_password(logged_in_client):
    client, csrf = logged_in_client
    response = client.post(
        "/api/staff",
        json={"username": "eight-char", "password": "A1!bcdef", "role": "warden"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201
    client.cookies.clear()
    login = client.post("/api/session", json={"username": "eight-char", "password": "A1!bcdef"})
    assert login.status_code == 200


def test_platform_portal_onboards_clients_and_keeps_owner_layout_access_separate(logged_in_client):
    client, owner_csrf = logged_in_client
    platform_csrf = login_platform(client)
    dashboard = client.get("/api/platform/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.json()["user"]["role"] == "developer"
    assert dashboard.json()["summary"]["total_clients"] == 1
    assert dashboard.json()["summary"]["subscription_received_count"] == 0
    assert dashboard.json()["summary"]["subscription_pending_count"] == 0

    created = client.post(
        "/api/platform/clients",
        json={
            "owner_username": "new-owner",
            "password": "New-owner-password1!",
            "hostel_name": "New Owner Hostel",
        },
        headers={"X-CSRF-Token": platform_csrf},
    )
    assert created.status_code == 201
    new_floor = client.post(
        f"/api/platform/hostels/{created.json()['hostel_id']}/floors",
        json={"floor_number": 1},
        headers={"X-CSRF-Token": platform_csrf},
    )
    assert new_floor.status_code == 201
    too_many_beds = client.post(
        f"/api/platform/floors/{new_floor.json()['id']}/rooms",
        json={"room_number": "501", "share_count": 5},
        headers={"X-CSRF-Token": platform_csrf},
    )
    assert too_many_beds.status_code == 422
    room = client.post(
        f"/api/platform/floors/{new_floor.json()['id']}/rooms",
        json={"room_number": "501", "share_count": 4},
        headers={"X-CSRF-Token": platform_csrf},
    )
    assert room.status_code == 201
    assert client.get("/api/platform/dashboard").json()["summary"]["total_clients"] == 2

    with TestClient(app) as new_owner_client:
        owner_login = new_owner_client.post(
            "/api/session", json={"username": "new-owner", "password": "New-owner-password1!"}
        )
        assert owner_login.status_code == 200
        owner_dashboard = new_owner_client.get("/api/dashboard").json()
        assert owner_dashboard["summary"]["total_rooms"] == 1
        assert len(owner_dashboard["hostels"][0]["floors"][0]["rooms"]) == 1
        assert new_owner_client.post(
            f"/api/platform/hostels/{created.json()['hostel_id']}/floors",
            json={"floor_number": 2},
            headers={"X-CSRF-Token": owner_login.json()["csrf_token"]},
        ).status_code == 401

    client.cookies.delete(config.PLATFORM_COOKIE_NAME)
    assert client.post(
        "/api/platform/hostels",
        json={"owner_id": "admin-id", "name": "Owner Must Not Create This"},
        headers={"X-CSRF-Token": owner_csrf},
    ).status_code == 401


def test_owner_room_type_charges_flow_through_rooms_vacancy_and_booking(logged_in_client):
    client, owner_csrf = logged_in_client
    saved = client.put(
        "/api/hostels/test-hostel/room-charges",
        json={
            "charges": [
                {"share_count": 2, "monthly_rent": 10000},
                {"share_count": 3, "monthly_rent": 8500},
                {"share_count": 4, "monthly_rent": 7500},
            ]
        },
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert saved.status_code == 200
    assert {item["share_count"]: item["monthly_rent_paise"] for item in saved.json()["charges"]} == {
        2: 1000000,
        3: 850000,
        4: 750000,
    }

    platform_headers = {"X-CSRF-Token": login_platform(client)}
    created_room = client.post(
        "/api/platform/floors/test-floor-1/rooms",
        json={"room_number": "102", "share_count": 2},
        headers=platform_headers,
    )
    assert created_room.status_code == 201
    assert created_room.json()["monthly_rent_paise"] == 1000000

    dashboard = client.get("/api/dashboard").json()
    room_rates = {room["share_count"]: room["monthly_rent_paise"] for room in dashboard["rooms"]}
    assert room_rates == {2: 1000000, 4: 750000}
    vacancy = client.get("/api/vacancy/live", params={"hostel_id": "test-hostel"}).json()
    four_share_vacancy = next(item for item in vacancy["vacant_list"] if item["share_count"] == 4)
    assert four_share_vacancy["rent"] == 7500

    booking = client.post(
        "/api/bookings/create",
        json={
            "name": "Rate Test Resident",
            "phone": "+919876543210",
            "sharing_needed": 4,
            "budget": 7500,
            "visit_time": "6pm",
            "hostel_id": "test-hostel",
        },
    )
    assert booking.status_code == 201
    confirmed = client.post(
        f"/api/bookings/confirm/{booking.json()['booking_id']}",
        headers={"X-CSRF-Token": owner_csrf},
    )
    assert confirmed.status_code == 200
    resident = next(
        item for item in client.get("/api/dashboard").json()["residents"] if item["id"] == confirmed.json()["resident_id"]
    )
    assert resident["amount_due_paise"] == 750000


def test_platform_subscription_payment_moves_from_pending_to_received(logged_in_client):
    client, _ = logged_in_client
    platform_csrf = login_platform(client)
    headers = {"X-CSRF-Token": platform_csrf}
    payload = {
        "owner_id": "admin-id",
        "billing_period": "2026-10",
        "amount": 12500,
        "due_date": "2026-10-31",
    }

    created = client.post("/api/platform/subscriptions", json=payload, headers=headers)
    assert created.status_code == 201
    dashboard = client.get("/api/platform/dashboard").json()
    assert dashboard["summary"]["subscription_received_count"] == 0
    assert dashboard["summary"]["subscription_received_paise"] == 0
    assert dashboard["summary"]["subscription_pending_count"] == 1
    assert dashboard["summary"]["subscription_pending_paise"] == 1250000
    assert dashboard["subscriptions"][0]["status"] == "pending"

    duplicate = client.post("/api/platform/subscriptions", json=payload, headers=headers)
    assert duplicate.status_code == 409

    received = client.patch(
        f"/api/platform/subscriptions/{created.json()['id']}/received",
        headers=headers,
    )
    assert received.status_code == 200
    dashboard = client.get("/api/platform/dashboard").json()
    assert dashboard["summary"]["subscription_received_count"] == 1
    assert dashboard["summary"]["subscription_received_paise"] == 1250000
    assert dashboard["summary"]["subscription_pending_count"] == 0
    assert dashboard["summary"]["subscription_pending_paise"] == 0
    assert dashboard["subscriptions"][0]["status"] == "received"


def test_cli_password_reset_updates_hash_and_revokes_sessions(logged_in_client, monkeypatch: pytest.MonkeyPatch):
    client, _ = logged_in_client
    new_password = "Updated-owner-password1!"
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
    created_booking = owner_client.post(
        "/api/bookings/create",
        json={
            "name": "Owner One Booking",
            "phone": "+919876543210",
            "sharing_needed": 4,
            "visit_time": "6pm",
            "hostel_id": "test-hostel",
        },
    )
    assert created_booking.status_code == 201

    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO staff (id, owner_id, username, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, 'admin', ?)",
            (
                "second-owner-id",
                "second-owner-id",
                "second-owner",
                hash_password("Second-owner-password1!"),
                "2026-01-01T00:00:00+00:00",
            ),
        )

    with TestClient(app) as other_owner_client:
        login = other_owner_client.post(
            "/api/session", json={"username": "second-owner", "password": "Second-owner-password1!"}
        )
        assert login.status_code == 200
        other_csrf = login.json()["csrf_token"]
        other_dashboard = other_owner_client.get("/api/dashboard").json()

        assert other_dashboard["hostels"] == []
        assert other_dashboard["rooms"] == []
        assert other_dashboard["residents"] == []
        assert other_dashboard["activity"] == []
        assert other_owner_client.get("/api/bookings").json() == []
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
        ).status_code == 401

    assert owner_client.get("/api/dashboard").json()["residents"][0]["id"] == resident_id
    assert len(owner_client.get("/api/bookings").json()) == 1


def test_multiple_hostels_floors_rooms_and_sharing_are_flexible(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}
    platform_headers = {"X-CSRF-Token": login_platform(client)}

    hostel = client.post(
        "/api/platform/hostels", json={"owner_id": "admin-id", "name": "West Campus"}, headers=platform_headers
    )
    assert hostel.status_code == 201
    hostel_id = hostel.json()["id"]
    first_floor = client.post(
        f"/api/platform/hostels/{hostel_id}/floors", json={"floor_number": 1}, headers=platform_headers
    )
    second_floor = client.post(
        f"/api/platform/hostels/{hostel_id}/floors", json={"floor_number": 2}, headers=platform_headers
    )
    assert first_floor.status_code == 201
    assert second_floor.status_code == 201
    empty_floors = client.get("/api/dashboard").json()
    north_campus = next(item for item in empty_floors["hostels"] if item["id"] == hostel_id)
    assert [floor["rooms"] for floor in north_campus["floors"]] == [[], []]

    for room_number in range(101, 106):
        created = client.post(
            f"/api/platform/floors/{first_floor.json()['id']}/rooms",
            json={"room_number": str(room_number), "share_count": 4},
            headers=platform_headers,
        )
        assert created.status_code == 201
    for room_number in range(201, 205):
        created = client.post(
            f"/api/platform/floors/{second_floor.json()['id']}/rooms",
            json={"room_number": str(room_number), "share_count": 4 if room_number == 201 else 3},
            headers=platform_headers,
        )
        assert created.status_code == 201

    structure = client.get("/api/dashboard").json()
    west_campus = next(item for item in structure["hostels"] if item["id"] == hostel_id)
    assert [len(floor["rooms"]) for floor in west_campus["floors"]] == [5, 4]
    assert structure["summary"]["capacity"] == 37

    resident = client.post(
        "/api/residents",
        data=resident_form(
            name="Sixth Bed Resident",
            aadhaar="",
            room=next(room["id"] for room in structure["rooms"] if room["room_number"] == "201"),
            bed_number="4",
            payment_status="paid",
            amount_due="",
        ),
        headers=headers,
    )
    assert resident.status_code == 201
    updated = client.get("/api/dashboard").json()
    room_201 = next(room for room in updated["rooms"] if room["room_number"] == "201")
    assert len(room_201["beds"]) == 4
    assert room_201["beds"][3]["occupied"] is True


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
    platform_headers = {"X-CSRF-Token": login_platform(client)}
    created = client.post("/api/residents", data=resident_form(payment_status="paid", amount_due=""), headers=headers)
    assert created.status_code == 201
    resident_id = created.json()["id"]

    occupied_delete = client.delete("/api/rooms/room-101", headers=platform_headers)
    assert occupied_delete.status_code == 409

    assert client.delete(f"/api/residents/{resident_id}", headers=headers).status_code == 200
    deleted = client.delete("/api/rooms/room-101", headers=platform_headers)
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
    with database.read_connection() as connection:
        assert connection.execute("SELECT 1 FROM audit_log WHERE action = 'room.delete'").fetchone()


def test_hostel_delete_requires_vacancy_and_archives_all_rooms(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}
    platform_headers = {"X-CSRF-Token": login_platform(client)}
    hostel = client.post(
        "/api/platform/hostels",
        json={"owner_id": "admin-id", "name": "Archive Test Hostel"},
        headers=platform_headers,
    )
    assert hostel.status_code == 201
    hostel_id = hostel.json()["id"]
    floor = client.post(
        f"/api/platform/hostels/{hostel_id}/floors", json={"floor_number": 1}, headers=platform_headers
    )
    room = client.post(
        f"/api/platform/floors/{floor.json()['id']}/rooms",
        json={"room_number": "601", "share_count": 4},
        headers=platform_headers,
    )
    resident = client.post(
        "/api/residents",
        data=resident_form(
            name="Hostel History Resident",
            aadhaar="",
            room=room.json()["id"],
            bed_number="4",
            payment_status="paid",
            amount_due="",
        ),
        headers=headers,
    )
    resident_id = resident.json()["id"]

    occupied_delete = client.delete(f"/api/hostels/{hostel_id}", headers=platform_headers)
    assert occupied_delete.status_code == 409

    assert client.delete(f"/api/residents/{resident_id}", headers=headers).status_code == 200
    deleted = client.delete(f"/api/hostels/{hostel_id}", headers=platform_headers)
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
    with database.read_connection() as connection:
        assert connection.execute("SELECT 1 FROM audit_log WHERE action = 'hostel.delete'").fetchone()


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
        room = connection.execute(
            "SELECT active, share_count, monthly_rent_paise FROM rooms WHERE id = ?", ("schema-room",)
        ).fetchone()
        hostel = connection.execute("SELECT active FROM hostels WHERE id = ?", ("schema-hostel",)).fetchone()
        version = connection.execute("SELECT 1 FROM schema_migrations WHERE version = 2").fetchone()
        rent_version = connection.execute("SELECT 1 FROM schema_migrations WHERE version = 5").fetchone()

    assert room["active"] == 1
    assert room["share_count"] == 6
    assert room["monthly_rent_paise"] == 0
    assert hostel["active"] == 1
    assert version is not None
    assert rent_version is not None


def test_booking_reserves_room_and_confirmation_creates_resident(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}

    vacancy = client.get("/api/vacancy/live", params={"hostel_id": "test-hostel"}).json()
    assert vacancy["total_rooms"] == 1
    assert vacancy["vacant_count"] == 1
    assert vacancy["vacant_list"][0]["room_no"] == "101"

    created = client.post(
        "/api/bookings/create",
        json={
            "name": "Booking Resident",
            "phone": "+919876543210",
            "sharing_needed": 4,
            "visit_time": "6pm",
            "hostel_id": "test-hostel",
        },
    )
    assert created.status_code == 201
    booking_id = created.json()["booking_id"]
    assert created.json()["room_no"] == "101"
    assert client.get("/api/vacancy/live", params={"hostel_id": "test-hostel"}).json()["vacant_count"] == 0

    dashboard = client.get("/api/dashboard").json()
    room = dashboard["rooms"][0]
    assert room["reserved"] is True
    assert room["available_beds"] == 0
    assert dashboard["summary"]["available"] == 0
    assert dashboard["bookings"][0]["student_name"] == "Booking Resident"
    assert client.post(
        "/api/residents",
        data=resident_form(room="room-101"),
        headers=headers,
    ).status_code == 409

    confirmed = client.post(f"/api/bookings/confirm/{booking_id}", headers=headers)
    assert confirmed.status_code == 200
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["residents"][0]["name"] == "Booking Resident"
    assert dashboard["residents"][0]["room"] == "101"
    assert dashboard["summary"]["available"] == 3
    assert dashboard["bookings"] == []
    with database.read_connection() as connection:
        booking = connection.execute("SELECT status FROM bookings WHERE id = ?", (booking_id,)).fetchone()
        resident = connection.execute("SELECT name_ciphertext, mobile_ciphertext FROM residents WHERE id = ?", (confirmed.json()["resident_id"],)).fetchone()
    assert booking["status"] == "joined"
    assert "Booking Resident" not in resident["name_ciphertext"]
    assert "9876543210" not in resident["mobile_ciphertext"]


def test_booking_budget_filter_and_cancel_release_room(logged_in_client):
    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}
    platform_headers = {"X-CSRF-Token": login_platform(client)}
    assert client.patch(
        "/api/rooms/room-101/rent", json={"monthly_rent": 6500}, headers=platform_headers
    ).status_code == 200
    floor = client.post(
        "/api/platform/hostels/test-hostel/floors", json={"floor_number": 2}, headers=platform_headers
    )
    assert floor.status_code == 201
    second_room = client.post(
        f"/api/platform/floors/{floor.json()['id']}/rooms",
        json={"room_number": "201", "share_count": 2, "monthly_rent": 5000},
        headers=platform_headers,
    )
    assert second_room.status_code == 201

    too_low = client.post(
        "/api/bookings/create",
        json={"name": "Budget Resident", "phone": "+919876543210", "sharing_needed": 2, "budget": 4500, "visit_time": "5pm", "hostel_id": "test-hostel"},
    )
    assert too_low.status_code == 409
    matched = client.post(
        "/api/bookings/create",
        json={"name": "Budget Resident", "phone": "+919876543210", "sharing_needed": 2, "budget": 5500, "visit_time": "5pm", "hostel_id": "test-hostel"},
    )
    assert matched.status_code == 201
    assert matched.json()["room_no"] == "201"
    cancelled = client.delete(f"/api/bookings/{matched.json()['booking_id']}", headers=headers)
    assert cancelled.status_code == 200
    assert client.get("/api/vacancy/live", params={"hostel_id": "test-hostel"}).json()["vacant_count"] == 2


def test_expired_booking_releases_room_and_cannot_be_confirmed(logged_in_client):
    client, csrf = logged_in_client
    booking = client.post(
        "/api/bookings/create",
        json={"name": "Expired Booking", "phone": "+919876543210", "visit_time": "7pm", "hostel_id": "test-hostel"},
    )
    assert booking.status_code == 201
    booking_id = booking.json()["booking_id"]
    with database.transaction() as connection:
        connection.execute(
            "UPDATE bookings SET reservation_expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", booking_id),
        )

    assert client.get("/api/vacancy/live", params={"hostel_id": "test-hostel"}).json()["vacant_count"] == 1
    assert client.get("/api/bookings").json() == []
    assert client.post(
        f"/api/bookings/confirm/{booking_id}", headers={"X-CSRF-Token": csrf}
    ).status_code == 404
    rebooked = client.post(
        "/api/bookings/create",
        json={"name": "New Visit", "phone": "+919876543211", "visit_time": "8pm", "hostel_id": "test-hostel"},
    )
    assert rebooked.status_code == 201


def test_qr_generation_and_signed_whatsapp_booking_flow(logged_in_client, monkeypatch: pytest.MonkeyPatch):
    import hashlib
    import hmac
    import json

    client, csrf = logged_in_client
    headers = {"X-CSRF-Token": csrf}
    platform_headers = {"X-CSRF-Token": login_platform(client)}
    monkeypatch.setattr(config, "WHATSAPP_BUSINESS_NUMBER", "919900001111")
    qr = client.get("/api/qr/test-hostel")
    assert qr.status_code == 200
    assert qr.headers["content-type"] == "image/png"
    assert qr.content.startswith(b"\x89PNG\r\n\x1a\n")

    monkeypatch.setattr(config, "WHATSAPP_VERIFY_TOKEN", "local-verify-token")
    verify = client.get(
        "/api/webhook/whatsapp",
        params={"hub.mode": "subscribe", "hub.verify_token": "local-verify-token", "hub.challenge": "12345"},
    )
    assert verify.status_code == 200
    assert verify.text == "12345"

    assert client.patch(
        "/api/rooms/room-101/rent", json={"monthly_rent": 6500}, headers=platform_headers
    ).status_code == 200
    monkeypatch.setattr(config, "WHATSAPP_APP_SECRET", "test-app-secret")
    monkeypatch.setattr(config, "WHATSAPP_ACCESS_TOKEN", "test-access-token")
    monkeypatch.setattr(config, "WHATSAPP_PHONE_NUMBER_ID", "test-phone-id")
    sent_messages: list[str] = []

    async def capture_message(to: str, message: str) -> None:
        sent_messages.append(message)

    monkeypatch.setattr("app.main._send_whatsapp_message", capture_message)
    incoming_messages = (
        "Hi CHECK VACANCY HOSTELID_test-hostel",
        "4 sharing, budget 6500",
        "my name is Rahul, visit at 6pm",
    )
    for text in incoming_messages:
        body = json.dumps(
            {"entry": [{"changes": [{"value": {"messages": [{"from": "919876543210", "text": {"body": text}}]}}]}]},
            separators=(",", ":"),
        ).encode()
        signature = "sha256=" + hmac.new(b"test-app-secret", body, hashlib.sha256).hexdigest()
        response = client.post(
            "/api/webhook/whatsapp",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": signature},
        )
        assert response.status_code == 200

    assert "1 rooms are vacant" in sent_messages[0]
    assert "Room 101" in sent_messages[1]
    assert "Room 101 reserved" in sent_messages[2]
    assert len(client.get("/api/bookings").json()) == 1


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
            json={"username": "first-admin", "password": "First-admin-test-password1!"},
        )
        assert remote_signup.status_code == 403

    with TestClient(app, client=("127.0.0.1", 5000)) as local_client:
        assert local_client.get("/api/setup-status").json() == {"setup_required": True}
        signup = local_client.post(
            "/api/setup-admin",
            json={"username": "first-admin", "password": "First-admin-test-password1!"},
        )
        assert signup.status_code == 201
        assert signup.json()["user"] == {"username": "first-admin", "role": "admin"}
        assert local_client.get("/api/session").json()["user"]["username"] == "first-admin"
        assert local_client.get("/api/setup-status").json() == {"setup_required": False}
        second_signup = local_client.post(
            "/api/setup-admin",
            json={"username": "second-admin", "password": "Second-admin-test-password1!"},
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