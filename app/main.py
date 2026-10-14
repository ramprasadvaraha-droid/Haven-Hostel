import json
import ipaddress
import re
import secrets
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import config, database
from app.security import decrypt_text, encrypt_bytes, encrypt_text, hash_address, hash_password
from app.security import hash_session_token, new_token, password_hasher, verify_password
from app.storage import read_document, remove_local_encrypted_document, save_encrypted_document


IMAGE_SIGNATURES = {
    "image/jpeg": lambda data: data.startswith(b"\xff\xd8\xff"),
    "image/png": lambda data: data.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/webp": lambda data: len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP",
}


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=1, max_length=200)


class InitialAdminRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=200)


class StaffRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=200)
    role: Literal["admin", "warden"]


class HostelRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class FloorRequest(BaseModel):
    floor_number: int = Field(ge=1, le=99)


class RoomRequest(BaseModel):
    room_number: str = Field(min_length=1, max_length=20, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    share_count: int = Field(ge=1, le=20)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if config.DATABASE_URL:
        if not config.BLOB_READ_WRITE_TOKEN:
            raise RuntimeError("BLOB_READ_WRITE_TOKEN is required when DATABASE_URL is configured.")
    else:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        config.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    database.initialize_database()
    encrypt_bytes(b"key-check")
    yield


app = FastAPI(title="Haven Hostel", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=config.ROOT_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
        "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index() -> FileResponse:
    return FileResponse(config.ROOT_DIR / "index.html", media_type="text/html")


@app.get("/api/index")
def api_index() -> FileResponse:
    return FileResponse(config.ROOT_DIR / "index.html", media_type="text/html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def is_loopback_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@app.get("/api/setup-status")
def setup_status(request: Request) -> dict[str, bool]:
    with database.read_connection() as connection:
        account_count = connection.execute("SELECT COUNT(*) FROM staff").fetchone()[0]
    return {"setup_required": account_count == 0 and is_loopback_request(request)}


@app.post("/api/setup-admin", status_code=201)
def setup_admin(payload: InitialAdminRequest, request: Request, response: Response) -> dict[str, object]:
    if not is_loopback_request(request):
        raise HTTPException(status_code=403, detail="Initial sign-up is only available from the local machine.")

    password_hash = hash_password(payload.password)
    staff_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    session_token, csrf_token = new_token(), new_token()
    try:
        with database.transaction() as connection:
            account_count = connection.execute("SELECT COUNT(*) FROM staff").fetchone()[0]
            if account_count:
                raise HTTPException(status_code=409, detail="Initial setup is already complete. Sign in instead.")
            connection.execute(
                "INSERT INTO staff (id, owner_id, username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, 'admin', ?)",
                (staff_id, staff_id, payload.username, password_hash, now.isoformat()),
            )
            database.write_audit(
                connection,
                staff_id,
                "staff.initial_signup",
                "staff",
                staff_id,
                {"username": payload.username, "role": "admin"},
            )
            connection.execute(
                "INSERT INTO sessions (token_hash, csrf_token, staff_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    hash_session_token(session_token),
                    csrf_token,
                    staff_id,
                    (now + timedelta(hours=config.SESSION_HOURS)).isoformat(),
                    now.isoformat(),
                ),
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That username is already in use.") from error

    response.set_cookie(
        config.COOKIE_NAME,
        session_token,
        max_age=config.SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"user": {"username": payload.username, "role": "admin"}, "csrf_token": csrf_token}


def current_staff(request: Request) -> dict[str, str]:
    raw_token = request.cookies.get(config.COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    now = datetime.now(timezone.utc).isoformat()
    with database.read_connection() as connection:
        row = connection.execute(
            "SELECT s.id, s.owner_id, s.username, s.role, s.active, ss.csrf_token, ss.expires_at "
            "FROM sessions ss JOIN staff s ON s.id = ss.staff_id WHERE ss.token_hash = ?",
            (hash_session_token(raw_token),),
        ).fetchone()
    if not row or not row["active"] or row["expires_at"] <= now:
        raise HTTPException(status_code=401, detail="Your session has expired. Sign in again.")
    request.state.csrf_token = row["csrf_token"]
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "username": row["username"],
        "role": row["role"],
    }


def require_write(request: Request, staff: dict[str, str] = Depends(current_staff)) -> dict[str, str]:
    provided = request.headers.get("x-csrf-token", "")
    if not provided or not secrets.compare_digest(provided, request.state.csrf_token):
        raise HTTPException(status_code=403, detail="Refresh your session before making changes.")
    return staff


def require_admin(staff: dict[str, str] = Depends(require_write)) -> dict[str, str]:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return staff


def record_failed_login(username: str, address_hash: str) -> None:
    attempted_at = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO login_attempts (username, address_hash, succeeded, attempted_at) VALUES (?, ?, 0, ?)",
            (username.casefold(), address_hash, attempted_at),
        )
        database.write_audit(connection, None, "auth.login_failed", "staff", None, {"username": username[:40]})
        connection.execute(
            "DELETE FROM login_attempts WHERE attempted_at < ?",
            ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),),
        )


@app.post("/api/session")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, object]:
    address = request.client.host if request.client else "unknown"
    address_hash = hash_address(address)
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=15)).isoformat()
    with database.read_connection() as connection:
        failures = connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND address_hash = ? "
            "AND succeeded = 0 AND attempted_at > ?",
            (payload.username.casefold(), address_hash, cutoff),
        ).fetchone()[0]
        row = connection.execute(
            "SELECT id, username, password_hash, role, active FROM staff WHERE username = ?",
            (payload.username,),
        ).fetchone()
    if failures >= 8:
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again in 15 minutes.")
    if row:
        valid_password = verify_password(row["password_hash"], payload.password)
    else:
        password_hasher.hash(payload.password)
        valid_password = False
    if not row or not row["active"] or not valid_password:
        record_failed_login(payload.username, address_hash)
        raise HTTPException(status_code=401, detail="Username or password is incorrect.")

    token, csrf_token = new_token(), new_token()
    expires_at = (now + timedelta(hours=config.SESSION_HOURS)).isoformat()
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, csrf_token, staff_id, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (hash_session_token(token), csrf_token, row["id"], expires_at, now.isoformat()),
        )
        connection.execute(
            "INSERT INTO login_attempts (username, address_hash, succeeded, attempted_at) VALUES (?, ?, 1, ?)",
            (payload.username.casefold(), address_hash, now.isoformat()),
        )
        database.write_audit(connection, row["id"], "auth.login", "staff", row["id"])
    response.set_cookie(
        config.COOKIE_NAME,
        token,
        max_age=config.SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"user": {"username": row["username"], "role": row["role"]}, "csrf_token": csrf_token}


@app.get("/api/session")
def session_info(request: Request, staff: dict[str, str] = Depends(current_staff)) -> dict[str, object]:
    return {"user": {"username": staff["username"], "role": staff["role"]}, "csrf_token": request.state.csrf_token}


@app.post("/api/session/logout")
def logout(request: Request, response: Response, staff: dict[str, str] = Depends(require_write)) -> dict[str, bool]:
    raw_token = request.cookies.get(config.COOKIE_NAME, "")
    with database.transaction() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (hash_session_token(raw_token),))
        database.write_audit(connection, staff["id"], "auth.logout", "staff", staff["id"])
    response.delete_cookie(config.COOKIE_NAME, path="/", httponly=True, secure=config.COOKIE_SECURE, samesite="strict")
    return {"ok": True}


def due_date_after_one_month(joining_date: date) -> date:
    month = joining_date.month % 12 + 1
    year = joining_date.year + int(joining_date.month == 12)
    following_month = month % 12 + 1
    following_year = year + int(month == 12)
    last_day = (date(following_year, following_month, 1) - timedelta(days=1)).day
    return date(year, month, min(joining_date.day, last_day))


def parse_date(value: str, field_name: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"Enter a valid {field_name}.") from error


def amount_to_paise(value: str) -> int:
    try:
        amount = Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError) as error:
        raise HTTPException(status_code=422, detail="Enter a valid outstanding balance.") from error
    if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000"):
        raise HTTPException(status_code=422, detail="Enter a valid outstanding balance.")
    return int(amount * 100)


async def read_optional_image(upload: UploadFile | None, label: str) -> tuple[bytes, str] | None:
    if not upload or not upload.filename:
        return None
    media_type = (upload.content_type or "").lower()
    signature_check = IMAGE_SIGNATURES.get(media_type)
    if not signature_check:
        raise HTTPException(status_code=422, detail=f"{label} must be a JPEG, PNG, or WebP image.")
    contents = await upload.read(config.MAX_DOCUMENT_BYTES + 1)
    if not contents or len(contents) > config.MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=413, detail=f"{label} must be 5 MB or smaller.")
    if not signature_check(contents):
        raise HTTPException(status_code=422, detail=f"{label} is not a valid {media_type.split('/')[-1].upper()} image.")
    return contents, media_type


def serialize_resident(row: sqlite3.Row, documents: list[dict[str, str]]) -> dict[str, object]:
    aadhaar = decrypt_text(row["aadhaar_ciphertext"]) if row["aadhaar_ciphertext"] else ""
    return {
        "id": row["id"],
        "name": decrypt_text(row["name_ciphertext"]),
        "mobile": decrypt_text(row["mobile_ciphertext"]),
        "aadhaar_last4": aadhaar[-4:] if aadhaar else "",
        "room_id": row["room_id"],
        "room": row["room_number"],
        "hostel_id": row["hostel_id"],
        "hostel_name": row["hostel_name"],
        "floor_number": row["floor_number"],
        "bed_number": row["bed_number"],
        "joining_date": row["joining_date"],
        "payment_due_date": row["payment_due_date"],
        "payment_status": row["payment_status"],
        "amount_due_paise": row["amount_due_paise"],
        "documents": documents,
    }


@app.get("/api/dashboard")
def dashboard(staff: dict[str, str] = Depends(current_staff)) -> dict[str, object]:
    with database.read_connection() as connection:
        rows = connection.execute(
            "SELECT resident.*, room.room_number, floor.floor_number, hostel.id AS hostel_id, "
            "hostel.name AS hostel_name FROM residents resident "
            "JOIN rooms room ON room.id = resident.room_id "
            "JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE resident.checked_out_at IS NULL AND hostel.owner_id = ? "
            "ORDER BY resident.joining_date DESC, resident.created_at DESC",
            (staff["owner_id"],),
        ).fetchall()
        documents = connection.execute(
            "SELECT d.id, d.resident_id, d.kind FROM documents d "
            "JOIN residents r ON r.id = d.resident_id "
            "JOIN rooms room ON room.id = r.room_id JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE r.checked_out_at IS NULL AND hostel.owner_id = ? "
            "ORDER BY CASE d.kind WHEN 'person_photo' THEN 0 ELSE 1 END",
            (staff["owner_id"],),
        ).fetchall()
        hostel_rows = connection.execute(
            "SELECT id, name FROM hostels WHERE active = 1 AND owner_id = ? ORDER BY name COLLATE NOCASE",
            (staff["owner_id"],),
        ).fetchall()
        floor_rows = connection.execute(
            "SELECT floor.id, floor.hostel_id, floor.floor_number FROM floors floor "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id WHERE hostel.active = 1 AND hostel.owner_id = ? "
            "ORDER BY floor.floor_number",
            (staff["owner_id"],),
        ).fetchall()
        room_rows = connection.execute(
            "SELECT room.id, room.room_number, room.share_count, room.floor_id, floor.floor_number, "
            "hostel.id AS hostel_id, hostel.name AS hostel_name "
            "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE room.active = 1 AND hostel.active = 1 AND hostel.owner_id = ? "
            "ORDER BY hostel.name COLLATE NOCASE, floor.floor_number, room.room_number COLLATE NOCASE",
            (staff["owner_id"],),
        ).fetchall()
        activity_rows = connection.execute(
            "SELECT a.action, a.entity_id, a.details_json, a.created_at, resident.name_ciphertext "
            "FROM audit_log a LEFT JOIN residents resident ON resident.id = a.entity_id "
            "JOIN staff actor ON actor.id = a.staff_id "
            "WHERE a.action IN ('resident.checkin', 'resident.checkout') AND actor.owner_id = ? "
            "ORDER BY a.created_at DESC LIMIT 8",
            (staff["owner_id"],),
        ).fetchall()

    documents_by_resident: dict[str, list[dict[str, str]]] = {}
    for document in documents:
        documents_by_resident.setdefault(document["resident_id"], []).append(
            {"kind": document["kind"], "url": f"/api/documents/{document['id']}"}
        )
    resident_data = [serialize_resident(row, documents_by_resident.get(row["id"], [])) for row in rows]
    residents_by_room: dict[str, set[int]] = {}
    for resident in resident_data:
        residents_by_room.setdefault(resident["room_id"], set()).add(resident["bed_number"])

    hostels_by_id: dict[str, dict[str, object]] = {
        row["id"]: {"id": row["id"], "name": row["name"], "floors": [], "occupied": 0}
        for row in hostel_rows
    }
    floors_by_id: dict[str, dict[str, object]] = {}
    for row in floor_rows:
        floor = {"id": row["id"], "floor_number": row["floor_number"], "rooms": []}
        floors_by_id[row["id"]] = floor
        hostel = hostels_by_id.get(row["hostel_id"])
        if hostel:
            hostel["floors"].append(floor)
    rooms: list[dict[str, object]] = []
    for row in room_rows:
        hostel = hostels_by_id.setdefault(
            row["hostel_id"],
            {"id": row["hostel_id"], "name": row["hostel_name"], "floors": [], "occupied": 0},
        )
        floor = floors_by_id.get(row["floor_id"])
        if floor is None:
            floor = {"id": row["floor_id"], "floor_number": row["floor_number"], "rooms": []}
            floors_by_id[row["floor_id"]] = floor
            hostel["floors"].append(floor)
        occupied_beds = residents_by_room.get(row["id"], set())
        room = {
            "id": row["id"],
            "room_number": row["room_number"],
            "share_count": row["share_count"],
            "hostel_id": row["hostel_id"],
            "hostel_name": row["hostel_name"],
            "floor_id": row["floor_id"],
            "floor_number": row["floor_number"],
            "occupied": len(occupied_beds),
            "beds": [
                {"number": number, "occupied": number in occupied_beds}
                for number in range(1, row["share_count"] + 1)
            ],
        }
        floor["rooms"].append(room)
        rooms.append(room)
        hostel["occupied"] += room["occupied"]
    activity = []
    for row in activity_rows:
        details = json.loads(row["details_json"])
        name = decrypt_text(row["name_ciphertext"]) if row["name_ciphertext"] else "Resident"
        activity.append(
            {
                "type": "exit" if row["action"] == "resident.checkout" else "join",
                "name": name,
                "room": details.get("room_number", details.get("room", "")),
                "hostel_name": details.get("hostel_name", ""),
                "floor_number": details.get("floor_number"),
                "bed_number": details.get("bed_number"),
                "time": row["created_at"],
            }
        )
    capacity = sum(room["share_count"] for room in rooms)
    return {
        "user": {"username": staff["username"], "role": staff["role"]},
        "summary": {
            "capacity": capacity,
            "occupied": len(resident_data),
            "available": capacity - len(resident_data),
            "rooms_open": sum(room["occupied"] < room["share_count"] for room in rooms),
            "outstanding_paise": sum(item["amount_due_paise"] for item in resident_data),
            "unpaid_count": sum(item["payment_status"] == "unpaid" for item in resident_data),
        },
        "hostels": list(hostels_by_id.values()),
        "rooms": rooms,
        "residents": resident_data,
        "activity": activity,
    }


@app.post("/api/hostels", status_code=201)
def create_hostel(payload: HostelRequest, staff: dict[str, str] = Depends(require_admin)) -> dict[str, str]:
    hostel_id = str(uuid.uuid4())
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Enter a hostel name.")
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO hostels (id, owner_id, name, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                (hostel_id, staff["owner_id"], name, staff["id"], datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                staff["id"],
                "hostel.create",
                "hostel",
                hostel_id,
                {"name": name},
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="A hostel with that name already exists.") from error
    return {"id": hostel_id, "name": name}


@app.delete("/api/hostels/{hostel_id}")
def delete_hostel(hostel_id: str, staff: dict[str, str] = Depends(require_admin)) -> dict[str, str]:
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id, name FROM hostels WHERE id = ? AND active = 1 AND owner_id = ?",
            (hostel_id, staff["owner_id"]),
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        occupied = connection.execute(
            "SELECT COUNT(*) FROM residents resident "
            "JOIN rooms room ON room.id = resident.room_id "
            "JOIN floors floor ON floor.id = room.floor_id "
            "WHERE floor.hostel_id = ? AND resident.checked_out_at IS NULL",
            (hostel_id,),
        ).fetchone()[0]
        if occupied:
            raise HTTPException(
                status_code=409,
                detail="Check out or move all current residents before deleting this hostel.",
            )
        connection.execute(
            "UPDATE rooms SET active = 0 WHERE floor_id IN (SELECT id FROM floors WHERE hostel_id = ?)",
            (hostel_id,),
        )
        connection.execute("UPDATE hostels SET active = 0 WHERE id = ?", (hostel_id,))
        database.write_audit(
            connection,
            staff["id"],
            "hostel.delete",
            "hostel",
            hostel_id,
            {"name": hostel["name"], "history_retained": True},
        )
    return {"status": "deleted", "name": hostel["name"]}


@app.post("/api/hostels/{hostel_id}/floors", status_code=201)
def create_floor(
    hostel_id: str,
    payload: FloorRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, object]:
    floor_id = str(uuid.uuid4())
    try:
        with database.transaction() as connection:
            hostel = connection.execute(
                "SELECT name FROM hostels WHERE id = ? AND active = 1 AND owner_id = ?",
                (hostel_id, staff["owner_id"]),
            ).fetchone()
            if not hostel:
                raise HTTPException(status_code=404, detail="Hostel not found.")
            connection.execute(
                "INSERT INTO floors (id, hostel_id, floor_number, created_at) VALUES (?, ?, ?, ?)",
                (floor_id, hostel_id, payload.floor_number, datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                staff["id"],
                "floor.create",
                "floor",
                floor_id,
                {"hostel_id": hostel_id, "floor_number": payload.floor_number},
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That floor already exists in this hostel.") from error
    return {"id": floor_id, "hostel_id": hostel_id, "floor_number": payload.floor_number, "name": floor_name(payload.floor_number)}


@app.post("/api/floors/{floor_id}/rooms", status_code=201)
def create_room(
    floor_id: str,
    payload: RoomRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, object]:
    room_id = str(uuid.uuid4())
    room_number = payload.room_number.strip()
    try:
        with database.transaction() as connection:
            floor = connection.execute(
                "SELECT floor_number, hostel.id AS hostel_id, hostel.name AS hostel_name "
                "FROM floors JOIN hostels hostel ON hostel.id = floors.hostel_id "
                "WHERE floors.id = ? AND hostel.active = 1 AND hostel.owner_id = ?",
                (floor_id, staff["owner_id"]),
            ).fetchone()
            if not floor:
                raise HTTPException(status_code=404, detail="Floor not found.")
            connection.execute(
                "INSERT INTO rooms (id, floor_id, room_number, share_count, created_at) VALUES (?, ?, ?, ?, ?)",
                (room_id, floor_id, room_number, payload.share_count, datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                staff["id"],
                "room.create",
                "room",
                room_id,
                {
                    "room_number": room_number,
                    "share_count": payload.share_count,
                    "floor_number": floor["floor_number"],
                    "hostel_name": floor["hostel_name"],
                },
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That room number already exists on this floor.") from error
    return {
        "id": room_id,
        "floor_id": floor_id,
        "room_number": room_number,
        "share_count": payload.share_count,
        "floor_number": floor["floor_number"],
        "hostel_id": floor["hostel_id"],
        "hostel_name": floor["hostel_name"],
    }


def floor_name(floor_number: int) -> str:
    suffix = "th" if 10 <= floor_number % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(floor_number % 10, "th")
    return f"{floor_number}{suffix} Floor"


@app.delete("/api/rooms/{room_id}")
def delete_room(room_id: str, staff: dict[str, str] = Depends(require_admin)) -> dict[str, str]:
    with database.transaction() as connection:
        room = connection.execute(
            "SELECT room.id, room.room_number, hostel.name AS hostel_name, floor.floor_number "
            "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE room.id = ? AND room.active = 1 AND hostel.owner_id = ?",
            (room_id, staff["owner_id"]),
        ).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="Active room not found.")
        occupied = connection.execute(
            "SELECT COUNT(*) FROM residents WHERE room_id = ? AND checked_out_at IS NULL",
            (room_id,),
        ).fetchone()[0]
        if occupied:
            raise HTTPException(status_code=409, detail="Check out or move current residents before deleting this room.")
        connection.execute("UPDATE rooms SET active = 0 WHERE id = ?", (room_id,))
        database.write_audit(
            connection,
            staff["id"],
            "room.delete",
            "room",
            room_id,
            {
                "room_number": room["room_number"],
                "hostel_name": room["hostel_name"],
                "floor_number": room["floor_number"],
                "history_retained": True,
            },
        )
    return {"status": "deleted", "room_number": room["room_number"]}


@app.post("/api/residents", status_code=201)
async def create_resident(
    name: str = Form(min_length=1, max_length=80),
    mobile: str = Form(min_length=10, max_length=20),
    aadhaar: str = Form(default="", max_length=14),
    room: str = Form(min_length=1, max_length=64),
    bed_number: int = Form(ge=1, le=20),
    joining_date: str = Form(),
    payment_status: Literal["paid", "unpaid"] = Form(),
    amount_due: str = Form(default=""),
    person_photo: UploadFile | None = File(default=None),
    aadhaar_photo: UploadFile | None = File(default=None),
    staff: dict[str, str] = Depends(require_write),
) -> dict[str, str]:
    name, mobile = name.strip(), mobile.strip()
    normalized_mobile = re.sub(r"[\s()-]", "", mobile)
    if not name or len(name) > 80:
        raise HTTPException(status_code=422, detail="Enter a valid full name.")
    if not re.fullmatch(r"\+?[0-9]{10,15}", normalized_mobile):
        raise HTTPException(status_code=422, detail="Enter a valid mobile number.")
    normalized_aadhaar = re.sub(r"\s", "", aadhaar)
    if normalized_aadhaar and not re.fullmatch(r"[0-9]{12}", normalized_aadhaar):
        raise HTTPException(status_code=422, detail="Aadhaar must contain 12 digits when provided.")
    joined = parse_date(joining_date, "joining date")
    payment_due = due_date_after_one_month(joined)
    amount_due_paise = amount_to_paise(amount_due) if payment_status == "unpaid" else 0
    if payment_status == "paid" and amount_due.strip():
        raise HTTPException(status_code=422, detail="A paid resident cannot have an outstanding balance.")

    person_image = await read_optional_image(person_photo, "Person photo")
    aadhaar_image = await read_optional_image(aadhaar_photo, "Aadhaar photo")
    resident_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    stored_documents: list[tuple[str, str, str]] = []
    try:
        for kind, image in (("person_photo", person_image), ("aadhaar_photo", aadhaar_image)):
            if image:
                contents, media_type = image
                stored_documents.append((save_encrypted_document(contents), kind, media_type))
        with database.transaction() as connection:
            room_record = connection.execute(
                "SELECT room.room_number, room.share_count, floor.floor_number, hostel.name AS hostel_name "
                "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
                "JOIN hostels hostel ON hostel.id = floor.hostel_id "
                "WHERE room.id = ? AND room.active = 1 AND hostel.owner_id = ?",
                (room, staff["owner_id"]),
            ).fetchone()
            if not room_record:
                raise HTTPException(status_code=422, detail="Choose a valid room.")
            if bed_number > room_record["share_count"]:
                raise HTTPException(status_code=422, detail="That bed number exceeds this room's sharing capacity.")
            connection.execute(
                "INSERT INTO residents (id, name_ciphertext, mobile_ciphertext, aadhaar_ciphertext, room_id, "
                "bed_number, joining_date, payment_due_date, payment_status, amount_due_paise, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    resident_id,
                    encrypt_text(name),
                    encrypt_text(normalized_mobile),
                    encrypt_text(normalized_aadhaar) if normalized_aadhaar else None,
                    room,
                    bed_number,
                    joined.isoformat(),
                    payment_due.isoformat(),
                    payment_status,
                    amount_due_paise,
                    staff["id"],
                    created_at,
                ),
            )
            for encrypted_path, kind, media_type in stored_documents:
                document_id = str(uuid.uuid4())
                connection.execute(
                    "INSERT INTO documents (id, resident_id, kind, encrypted_path, media_type, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (document_id, resident_id, kind, encrypted_path, media_type, created_at),
                )
                database.write_audit(
                    connection,
                    staff["id"],
                    "document.upload",
                    "document",
                    document_id,
                    {"resident_id": resident_id, "kind": kind},
                )
            database.write_audit(
                connection,
                staff["id"],
                "resident.checkin",
                "resident",
                resident_id,
                {
                    "room": room_record["room_number"],
                    "room_id": room,
                    "room_number": room_record["room_number"],
                    "hostel_name": room_record["hostel_name"],
                    "floor_number": room_record["floor_number"],
                    "bed_number": bed_number,
                    "payment_status": payment_status,
                    "amount_due_paise": amount_due_paise,
                    "payment_due_date": payment_due.isoformat(),
                },
            )
    except sqlite3.IntegrityError as error:
        for encrypted_path, _, _ in stored_documents:
            remove_local_encrypted_document(encrypted_path)
        if "residents.room_id, residents.bed_number" in str(error):
            raise HTTPException(status_code=409, detail="That bed is already occupied. Choose another bed.") from error
        raise HTTPException(status_code=409, detail="This resident could not be registered.") from error
    except Exception:
        for encrypted_path, _, _ in stored_documents:
            remove_local_encrypted_document(encrypted_path)
        raise
    return {"id": resident_id}


@app.post("/api/residents/{resident_id}/payment")
def mark_payment_paid(resident_id: str, staff: dict[str, str] = Depends(require_write)) -> dict[str, str]:
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT resident.amount_due_paise, resident.payment_status FROM residents resident "
            "JOIN rooms room ON room.id = resident.room_id JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE resident.id = ? AND resident.checked_out_at IS NULL AND hostel.owner_id = ?",
            (resident_id, staff["owner_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Active resident not found.")
        connection.execute(
            "UPDATE residents SET payment_status = 'paid', amount_due_paise = 0 WHERE id = ?",
            (resident_id,),
        )
        database.write_audit(
            connection,
            staff["id"],
            "payment.mark_paid",
            "resident",
            resident_id,
            {"previous_status": row["payment_status"], "amount_paid_paise": row["amount_due_paise"]},
        )
    return {"status": "paid"}


@app.delete("/api/residents/{resident_id}")
def checkout_resident(resident_id: str, staff: dict[str, str] = Depends(require_write)) -> dict[str, str]:
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT resident.room_id, resident.bed_number, room.room_number, floor.floor_number, hostel.name AS hostel_name "
            "FROM residents resident JOIN rooms room ON room.id = resident.room_id "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE resident.id = ? AND resident.checked_out_at IS NULL AND hostel.owner_id = ?",
            (resident_id, staff["owner_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Active resident not found.")
        connection.execute(
            "UPDATE residents SET checked_out_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), resident_id),
        )
        database.write_audit(
            connection,
            staff["id"],
            "resident.checkout",
            "resident",
            resident_id,
            {
                "room_id": row["room_id"],
                "room": row["room_number"],
                "floor_number": row["floor_number"],
                "hostel_name": row["hostel_name"],
                "bed_number": row["bed_number"],
            },
        )
    return {"status": "checked_out"}


@app.get("/api/documents/{document_id}")
def download_document(document_id: str, staff: dict[str, str] = Depends(current_staff)) -> Response:
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT document.encrypted_path, document.media_type, document.resident_id FROM documents document "
            "JOIN residents resident ON resident.id = document.resident_id "
            "JOIN rooms room ON room.id = resident.room_id JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE document.id = ? AND hostel.owner_id = ?",
            (document_id, staff["owner_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Document not found.")
        database.write_audit(
            connection,
            staff["id"],
            "document.download",
            "document",
            document_id,
            {"resident_id": row["resident_id"]},
        )
    return Response(
        content=read_document(row["encrypted_path"]),
        media_type=row["media_type"],
        headers={"Content-Disposition": "attachment; filename=resident-document", "Cache-Control": "no-store"},
    )


@app.get("/api/audit")
def audit_log(limit: int = 100, staff: dict[str, str] = Depends(current_staff)) -> list[dict[str, object]]:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    limit = max(1, min(limit, 500))
    with database.read_connection() as connection:
        rows = connection.execute(
            "SELECT a.action, a.entity_type, a.entity_id, a.details_json, a.created_at, s.username "
            "FROM audit_log a LEFT JOIN staff s ON s.id = a.staff_id "
            "WHERE a.staff_id IN (SELECT id FROM staff WHERE owner_id = ?) "
            "ORDER BY a.created_at DESC LIMIT ?",
            (staff["owner_id"], limit),
        ).fetchall()
    return [
        {
            "action": row["action"],
            "entity_type": row["entity_type"],
            "entity_id": row["entity_id"],
            "details": json.loads(row["details_json"]),
            "created_at": row["created_at"],
            "staff_username": row["username"] or "system",
        }
        for row in rows
    ]


@app.get("/api/staff")
def list_staff(staff: dict[str, str] = Depends(current_staff)) -> list[dict[str, object]]:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    with database.read_connection() as connection:
        rows = connection.execute(
            "SELECT id, username, role, active, created_at FROM staff WHERE owner_id = ? ORDER BY username",
            (staff["owner_id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/staff", status_code=201)
def create_staff(payload: StaffRequest, staff: dict[str, str] = Depends(require_admin)) -> dict[str, str]:
    staff_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO staff (id, owner_id, username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    staff_id,
                    staff_id if payload.role == "admin" else staff["owner_id"],
                    payload.username,
                    hash_password(payload.password),
                    payload.role,
                    created_at,
                ),
            )
            database.write_audit(
                connection,
                staff["id"],
                "staff.create",
                "staff",
                staff_id,
                {"username": payload.username, "role": payload.role},
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That username is already in use.") from error
    return {"id": staff_id, "username": payload.username, "role": payload.role}