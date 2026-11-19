import asyncio
import json
import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import smtplib
import sqlite3
import ssl
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from email.message import EmailMessage
from io import BytesIO
from typing import Literal
from zoneinfo import ZoneInfo

import httpx
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from urllib.parse import quote

from app import config, database
from app.security import decrypt_text, encrypt_bytes, encrypt_text, hash_address, hash_password, password_policy_error
from app.security import hash_session_token, new_token, password_hasher, verify_password
from app.storage import (
    document_storage_ready,
    read_document,
    remove_local_encrypted_document,
    save_encrypted_document,
)
from app.retention import purge_expired_records


IMAGE_SIGNATURES = {
    "image/jpeg": lambda data: data.startswith(b"\xff\xd8\xff"),
    "image/png": lambda data: data.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/webp": lambda data: len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP",
}
REGISTRATION_TERMS_VERSION = "hostel-rules-v1"


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=1, max_length=200)


class StrongPasswordRequest(BaseModel):
    password: str = Field(min_length=8, max_length=200)

    @field_validator("password")
    @classmethod
    def password_meets_policy(cls, password: str) -> str:
        error = password_policy_error(password)
        if error:
            raise ValueError(error)
        return password


class InitialAdminRequest(StrongPasswordRequest):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")


class StaffRequest(StrongPasswordRequest):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    role: Literal["admin", "warden"]


class PlatformLoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=1, max_length=200)


class PlatformPasswordChangeRequest(StrongPasswordRequest):
    current_password: str = Field(min_length=1, max_length=200)


class PlatformPasswordResetRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)


class PlatformPasswordResetConfirmRequest(StrongPasswordRequest):
    username: str = Field(min_length=3, max_length=40)
    code: str = Field(min_length=8, max_length=8, pattern=r"^[0-9]{8}$")


class PlatformClientRequest(StrongPasswordRequest):
    owner_username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    hostel_name: str = Field(min_length=2, max_length=100)
    hostel_address: str = Field(min_length=5, max_length=300)
    location: str | None = Field(default=None, max_length=160)
    owner_mobile: str = Field(min_length=10, max_length=20, pattern=r"^\+?[0-9\s().-]{10,20}$")

    @field_validator("hostel_address")
    @classmethod
    def address_is_not_blank(cls, address: str) -> str:
        if not address.strip():
            raise ValueError("Enter the hostel address.")
        return address.strip()

    @field_validator("location")
    @classmethod
    def clean_optional_location(cls, location: str | None) -> str | None:
        return location.strip() or None if location else None


class PlatformHostelRequest(BaseModel):
    owner_id: str
    name: str = Field(min_length=2, max_length=100)


class PlatformHostelSetupRequest(BaseModel):
    ac_type: Literal["ac", "mixed"]
    floor_types: list[Literal["basement", "ground", "penthouse"]] = Field(default_factory=list, max_length=3)
    upper_floor_count: int = Field(ge=0, le=99)

    @field_validator("floor_types")
    @classmethod
    def floor_types_are_unique(cls, floor_types: list[str]) -> list[str]:
        if len(floor_types) != len(set(floor_types)):
            raise ValueError("Choose each floor type only once.")
        return floor_types


class PlatformSubscriptionRequest(BaseModel):
    owner_id: str
    billing_period: str = Field(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")
    amount: Decimal = Field(gt=0, le=1000000)
    due_date: date


class HostelRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)


class FloorRequest(BaseModel):
    floor_number: int = Field(ge=1, le=99)
    floor_type: Literal["basement", "ground", "standard", "penthouse"] = "standard"


class RoomRequest(BaseModel):
    room_number: str = Field(min_length=1, max_length=20, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    share_count: int = Field(ge=1, le=20)
    ac_type: Literal["ac", "non_ac"] | None = None
    monthly_rent: Decimal = Field(default=Decimal("0"), ge=0, le=1000000)


class RoomRentRequest(BaseModel):
    monthly_rent: Decimal = Field(ge=0, le=1000000)


class RoomTypeChargeItem(BaseModel):
    share_count: int = Field(ge=1, le=20)
    ac_type: Literal["ac", "non_ac"] | None = None
    monthly_rent: Decimal = Field(ge=0, le=1000000)


class RoomTypeChargesRequest(BaseModel):
    charges: list[RoomTypeChargeItem] = Field(min_length=1, max_length=40)


class BookingCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    phone: str = Field(min_length=10, max_length=20)
    sharing_needed: int | None = Field(default=None, ge=1, le=20)
    budget: Decimal | None = Field(default=None, gt=0, le=1000000)
    visit_time: str = Field(min_length=1, max_length=100)
    hostel_id: str | None = None


class RegistrationInviteRequest(BaseModel):
    hostel_id: str = Field(min_length=1, max_length=64)
    expires_in_days: int = Field(default=7, ge=1, le=30)


class RegistrationApprovalRequest(BaseModel):
    room_id: str = Field(min_length=1, max_length=64)
    bed_number: int = Field(ge=1, le=20)
    joining_date: str = Field(min_length=1, max_length=10)
    payment_status: Literal["paid", "unpaid"]
    amount_due: Decimal = Field(default=Decimal("0"), ge=0, le=1000000)


class WhatsAppConsentRequest(BaseModel):
    enabled: bool


class WhatsAppBroadcastRequest(BaseModel):
    hostel_id: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=1024)


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
logger = logging.getLogger(__name__)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' "
        "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://images.unsplash.com; "
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


@app.get("/register/{token}")
def registration_page(token: str) -> FileResponse:
    if not re.fullmatch(r"[a-f0-9]{64}", token):
        raise HTTPException(status_code=404, detail="Registration link not found.")
    return FileResponse(
        config.ROOT_DIR / "static" / "registration.html",
        media_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/cron/retention")
def run_retention_cleanup(request: Request) -> dict[str, object]:
    if not config.CRON_SECRET:
        raise HTTPException(status_code=503, detail="CRON_SECRET is not configured.")
    if not hmac.compare_digest(
        request.headers.get("authorization", ""),
        f"Bearer {config.CRON_SECRET}",
    ):
        raise HTTPException(status_code=401, detail="Invalid cron authorization.")
    result = purge_expired_records()
    if result["cleanup_failures"]:
        logger.error(
            "Retention cleanup left %s expired record(s) pending document deletion.",
            result["cleanup_failures"],
        )
        raise HTTPException(
            status_code=503,
            detail="Some expired documents could not be deleted; the next scheduled run will retry.",
        )
    return result


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


def require_admin_read(staff: dict[str, str] = Depends(current_staff)) -> dict[str, str]:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return staff


def require_staff_or_platform(request: Request) -> dict[str, str]:
    if request.cookies.get(config.PLATFORM_COOKIE_NAME):
        account = current_platform_user(request)
        if account.get("role") != "developer":
            raise HTTPException(status_code=403, detail="Administrator access is required.")
        return account
    staff = current_staff(request)
    if staff.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return staff


def current_platform_user(request: Request) -> dict[str, str]:
    raw_token = request.cookies.get(config.PLATFORM_COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Sign in to the employer portal.")
    now = datetime.now(timezone.utc).isoformat()
    with database.read_connection() as connection:
        row = connection.execute(
            "SELECT account.id, account.username, account.active, session.csrf_token, session.expires_at "
            "FROM platform_sessions session JOIN platform_accounts account ON account.id = session.account_id "
            "WHERE session.token_hash = ?",
            (hash_session_token(raw_token),),
        ).fetchone()
    if not row or not row["active"] or row["expires_at"] <= now:
        raise HTTPException(status_code=401, detail="Your employer session has expired. Sign in again.")
    request.state.platform_csrf_token = row["csrf_token"]
    return {"id": row["id"], "username": row["username"], "role": "developer"}


def require_platform_write(
    request: Request,
    account: dict[str, str] = Depends(current_platform_user),
) -> dict[str, str]:
    provided = request.headers.get("x-csrf-token", "")
    if not provided or not secrets.compare_digest(provided, request.state.platform_csrf_token):
        raise HTTPException(status_code=403, detail="Refresh your employer session before making changes.")
    return account


@app.post("/api/platform/session")
def platform_login(payload: PlatformLoginRequest, request: Request, response: Response) -> dict[str, object]:
    address = request.client.host if request.client else "unknown"
    address_hash = hash_address(address)
    username_key = f"platform:{payload.username.casefold()}"
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    with database.read_connection() as connection:
        failures = connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND address_hash = ? "
            "AND succeeded = 0 AND attempted_at > ?",
            (username_key, address_hash, cutoff),
        ).fetchone()[0]
        account = connection.execute(
            "SELECT id, username, password_hash, active FROM platform_accounts WHERE username = ?",
            (payload.username,),
        ).fetchone()
    if failures >= 8:
        raise HTTPException(status_code=429, detail="Too many employer sign-in attempts. Try again in 15 minutes.")
    if account:
        valid_password = verify_password(account["password_hash"], payload.password)
    else:
        password_hasher.hash(payload.password)
        valid_password = False
    if not account or not account["active"] or not valid_password:
        record_failed_login(username_key, address_hash)
        raise HTTPException(status_code=401, detail="Employer username or password is incorrect.")
    token, csrf_token = new_token(), new_token()
    now = datetime.now(timezone.utc)
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO platform_sessions (token_hash, csrf_token, account_id, expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                hash_session_token(token),
                csrf_token,
                account["id"],
                (now + timedelta(hours=config.SESSION_HOURS)).isoformat(),
                now.isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO login_attempts (username, address_hash, succeeded, attempted_at) VALUES (?, ?, 1, ?)",
            (username_key, address_hash, now.isoformat()),
        )
    response.set_cookie(
        config.PLATFORM_COOKIE_NAME,
        token,
        max_age=config.SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"user": {"username": account["username"], "role": "developer"}, "csrf_token": csrf_token}


@app.get("/api/platform/session")
def platform_session_info(request: Request, account: dict[str, str] = Depends(current_platform_user)) -> dict[str, object]:
    return {"user": account, "csrf_token": request.state.platform_csrf_token}


@app.post("/api/platform/session/logout")
def platform_logout(
    request: Request,
    response: Response,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, bool]:
    raw_token = request.cookies.get(config.PLATFORM_COOKIE_NAME, "")
    with database.transaction() as connection:
        connection.execute("DELETE FROM platform_sessions WHERE token_hash = ?", (hash_session_token(raw_token),))
    response.delete_cookie(
        config.PLATFORM_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=config.COOKIE_SECURE,
        samesite="strict",
    )
    return {"ok": True}


def record_failed_login(username: str, address_hash: str) -> None:
    attempted_at = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO login_attempts (username, address_hash, succeeded, attempted_at) VALUES (?, ?, 0, ?)",
            (username.casefold(), address_hash, attempted_at),
        )


@app.post("/api/platform/session/password")
def change_platform_password(
    payload: PlatformPasswordChangeRequest,
    request: Request,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, str]:
    with database.transaction() as connection:
        account_row = connection.execute(
            "SELECT password_hash FROM platform_accounts WHERE id = ? AND active = 1",
            (account["id"],),
        ).fetchone()
        if not account_row or not verify_password(account_row["password_hash"], payload.current_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        connection.execute(
            "UPDATE platform_accounts SET password_hash = ? WHERE id = ?",
            (hash_password(payload.password), account["id"]),
        )
        current_token = hash_session_token(request.cookies.get(config.PLATFORM_COOKIE_NAME, ""))
        connection.execute(
            "DELETE FROM platform_sessions WHERE account_id = ? AND token_hash <> ?",
            (account["id"], current_token),
        )
        database.write_audit(connection, None, "platform.password_change", "platform_account", account["id"])
    return {"status": "updated"}


@app.post("/api/platform/password/forgot")
def request_platform_password_reset(payload: PlatformPasswordResetRequest, request: Request) -> dict[str, str]:
    if not config.HOSTEL_SMTP_HOST or not config.HOSTEL_SMTP_FROM:
        raise HTTPException(status_code=503, detail="Employer password recovery is not configured. Contact the platform administrator.")

    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    cutoff = (now - timedelta(minutes=15)).isoformat()
    address = request.client.host if request.client else "unknown"
    address_hash = hash_address(address)
    username_key = f"platform:reset:{payload.username.casefold()}"
    code = f"{secrets.randbelow(100_000_000):08d}"
    reset_id = str(uuid.uuid4())
    recovery_email = None
    with database.transaction() as connection:
        failures = connection.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND address_hash = ? "
            "AND succeeded = 0 AND attempted_at > ?",
            (username_key, address_hash, cutoff),
        ).fetchone()[0]
        if failures < 5:
            connection.execute(
                "INSERT INTO login_attempts (username, address_hash, succeeded, attempted_at) VALUES (?, ?, 0, ?)",
                (username_key, address_hash, now_text),
            )
            account_row = connection.execute(
                "SELECT id, recovery_email FROM platform_accounts WHERE username = ? AND active = 1",
                (payload.username,),
            ).fetchone()
            if account_row and account_row["recovery_email"]:
                recent_resets = connection.execute(
                    "SELECT COUNT(*) FROM platform_password_resets WHERE account_id = ? AND created_at > ?",
                    (account_row["id"], (now - timedelta(hours=1)).isoformat()),
                ).fetchone()[0]
                if recent_resets < 3:
                    recovery_email = account_row["recovery_email"]
                    connection.execute("DELETE FROM platform_password_resets WHERE account_id = ?", (account_row["id"],))
                    connection.execute(
                        "INSERT INTO platform_password_resets (id, account_id, code_hash, attempts, expires_at, created_at) "
                        "VALUES (?, ?, ?, 0, ?, ?)",
                        (
                            reset_id,
                            account_row["id"],
                            hash_password(code),
                            (now + timedelta(minutes=15)).isoformat(),
                            now_text,
                        ),
                    )
    if not recovery_email:
        password_hasher.hash(payload.username)
        return {"message": "If an active Employer account has a recovery email, a code has been sent."}
    try:
        send_platform_password_reset_code(recovery_email, code)
    except (OSError, smtplib.SMTPException, RuntimeError):
        logger.exception("Failed to send an Employer password reset email")
        with database.transaction() as connection:
            connection.execute("DELETE FROM platform_password_resets WHERE id = ?", (reset_id,))
    return {"message": "If an active Employer account has a recovery email, a code has been sent."}


@app.post("/api/platform/password/reset")
def reset_platform_password(payload: PlatformPasswordResetConfirmRequest) -> dict[str, str]:
    now_text = datetime.now(timezone.utc).isoformat()
    reset_succeeded = False
    with database.transaction() as connection:
        account = connection.execute(
            "SELECT id FROM platform_accounts WHERE username = ? AND active = 1",
            (payload.username,),
        ).fetchone()
        reset = connection.execute(
            "SELECT id, code_hash, attempts FROM platform_password_resets "
            "WHERE account_id = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 1",
            (account["id"], now_text),
        ).fetchone() if account else None
        if reset and reset["attempts"] < 5 and verify_password(reset["code_hash"], payload.code):
            connection.execute(
                "UPDATE platform_accounts SET password_hash = ? WHERE id = ?",
                (hash_password(payload.password), account["id"]),
            )
            connection.execute("DELETE FROM platform_sessions WHERE account_id = ?", (account["id"],))
            connection.execute("DELETE FROM platform_password_resets WHERE account_id = ?", (account["id"],))
            database.write_audit(connection, None, "platform.password_reset", "platform_account", account["id"])
            reset_succeeded = True
        elif reset:
            connection.execute(
                "UPDATE platform_password_resets SET attempts = attempts + 1 WHERE id = ?",
                (reset["id"],),
            )
    if not reset_succeeded:
        raise HTTPException(status_code=400, detail="The reset code is invalid or expired.")
    return {"status": "reset"}


def send_platform_password_reset_code(email_address: str, code: str) -> None:
    if not config.HOSTEL_SMTP_HOST or not config.HOSTEL_SMTP_FROM:
        raise RuntimeError("Employer password recovery email is not configured.")
    message = EmailMessage()
    message["Subject"] = "Your Haven Hostel password reset code"
    message["From"] = config.HOSTEL_SMTP_FROM
    message["To"] = email_address
    message.set_content(
        f"Your Haven Hostel Employer password reset code is {code}. "
        "It expires in 15 minutes. If you did not request this code, you can ignore this email."
    )
    smtp_class = smtplib.SMTP_SSL if config.HOSTEL_SMTP_USE_SSL else smtplib.SMTP
    smtp_options = {"timeout": 10}
    if config.HOSTEL_SMTP_USE_SSL:
        smtp_options["context"] = ssl.create_default_context()
    with smtp_class(config.HOSTEL_SMTP_HOST, config.HOSTEL_SMTP_PORT, **smtp_options) as smtp:
        if not config.HOSTEL_SMTP_USE_SSL:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        if config.HOSTEL_SMTP_USERNAME:
            smtp.login(config.HOSTEL_SMTP_USERNAME, config.HOSTEL_SMTP_PASSWORD)
        smtp.send_message(message)
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


def rent_to_paise(value: str) -> int:
    try:
        amount = Decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError) as error:
        raise HTTPException(status_code=422, detail="Enter a valid monthly rent.") from error
    if not amount.is_finite() or amount < 0 or amount > Decimal("1000000"):
        raise HTTPException(status_code=422, detail="Enter a valid monthly rent.")
    return int(amount * 100)


def room_type_charge_or_fallback(
    connection: sqlite3.Connection | database.PostgresConnection,
    hostel_id: str,
    share_count: int,
    ac_type: str,
    fallback_paise: int,
) -> int:
    charge = connection.execute(
        "SELECT monthly_rent_paise FROM room_type_charges "
        "WHERE hostel_id = ? AND share_count = ? AND ac_type = ?",
        (hostel_id, share_count, ac_type),
    ).fetchone()
    return charge["monthly_rent_paise"] if charge else fallback_paise


async def read_optional_image(upload: UploadFile | None, label: str) -> tuple[bytes, str] | None:
    if not upload or not upload.filename:
        return None
    if not document_storage_ready():
        raise HTTPException(
            status_code=503,
            detail="Secure document storage is not configured. Contact the administrator.",
        )
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


async def read_required_image(upload: UploadFile, label: str) -> tuple[bytes, str]:
    image = await read_optional_image(upload, label)
    if image is None:
        raise HTTPException(status_code=422, detail=f"{label} is required.")
    return image


def serialize_resident(row: sqlite3.Row, documents: list[dict[str, str]]) -> dict[str, object]:
    aadhaar = decrypt_text(row["aadhaar_ciphertext"]) if row["aadhaar_ciphertext"] else ""
    return {
        "id": row["id"],
        "name": decrypt_text(row["name_ciphertext"]),
        "mobile": decrypt_text(row["mobile_ciphertext"]),
        "emergency_contact": decrypt_text(row["emergency_contact_ciphertext"])
        if row["emergency_contact_ciphertext"]
        else "",
        "emergency_contact_relationship": decrypt_text(row["emergency_contact_relationship_ciphertext"])
        if row["emergency_contact_relationship_ciphertext"]
        else "",
        "aadhaar_last4": aadhaar[-4:] if aadhaar else "",
        "purpose_of_stay": decrypt_text(row["purpose_of_stay_ciphertext"])
        if row["purpose_of_stay_ciphertext"]
        else "",
        "office_address": decrypt_text(row["office_address_ciphertext"])
        if row["office_address_ciphertext"]
        else "",
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
        "whatsapp_opt_in": bool(row["whatsapp_opt_in"]),
        "terms_accepted_at": row["terms_accepted_at"],
        "documents": documents,
    }


@app.get("/api/dashboard")
def dashboard(staff: dict[str, str] = Depends(current_staff)) -> dict[str, object]:
    with database.read_connection() as connection:
        rows = connection.execute(
            "SELECT resident.*, room.room_number, floor.floor_number, hostel.id AS hostel_id, "
            "hostel.name AS hostel_name, "
            "(SELECT MAX(application.terms_accepted_at) FROM registration_applications application "
            "WHERE application.resident_id = resident.id) AS terms_accepted_at "
            "FROM residents resident "
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
            "SELECT id, name, ac_type, address_ciphertext, location_ciphertext, owner_mobile_ciphertext "
            "FROM hostels WHERE active = 1 AND owner_id = ? ORDER BY name COLLATE NOCASE",
            (staff["owner_id"],),
        ).fetchall()
        room_type_charge_rows = connection.execute(
            "SELECT charge.hostel_id, charge.share_count, charge.ac_type, charge.monthly_rent_paise "
            "FROM room_type_charges charge JOIN hostels hostel ON hostel.id = charge.hostel_id "
            "WHERE hostel.active = 1 AND hostel.owner_id = ? ORDER BY charge.hostel_id, charge.share_count",
            (staff["owner_id"],),
        ).fetchall()
        floor_rows = connection.execute(
            "SELECT floor.id, floor.hostel_id, floor.floor_number, floor.floor_type FROM floors floor "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE CAST(floor.active AS TEXT) IN ('1', 'true') AND hostel.active = 1 AND hostel.owner_id = ? "
            "ORDER BY floor.floor_number",
            (staff["owner_id"],),
        ).fetchall()
        room_rows = connection.execute(
            "SELECT room.id, room.room_number, room.share_count, room.ac_type, room.monthly_rent_paise, room.floor_id, floor.floor_number, "
            "hostel.id AS hostel_id, hostel.name AS hostel_name "
            "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE room.active = 1 AND hostel.active = 1 AND hostel.owner_id = ? "
            "ORDER BY hostel.name COLLATE NOCASE, floor.floor_number, room.room_number COLLATE NOCASE",
            (staff["owner_id"],),
        ).fetchall()
        now_text = datetime.now(timezone.utc).isoformat()
        booking_rows = connection.execute(
            "SELECT booking.*, room.room_number, room.share_count, room.monthly_rent_paise, "
            "floor.floor_number, hostel.name AS hostel_name FROM bookings booking "
            "JOIN rooms room ON room.id = booking.room_id_reserved "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE booking.owner_id = ? AND booking.status = 'visit_booked' AND booking.cancelled_at IS NULL "
            "AND booking.reservation_expires_at > ? AND hostel.active = 1 "
            "ORDER BY booking.visit_time, booking.created_at",
            (staff["owner_id"], now_text),
        ).fetchall()
        activity_rows = []
        for action in ("resident.checkin", "resident.checkout"):
            activity_rows.extend(
                connection.execute(
                    "SELECT a.action, a.entity_id, a.details_json, a.created_at, resident.name_ciphertext "
                    "FROM audit_log a LEFT JOIN residents resident ON resident.id = a.entity_id "
                    "JOIN staff actor ON actor.id = a.staff_id "
                    "WHERE a.action = ? AND actor.owner_id = ? "
                    "ORDER BY a.created_at DESC LIMIT 5",
                    (action, staff["owner_id"]),
                ).fetchall()
            )
        activity_rows.sort(key=lambda row: row["created_at"], reverse=True)

    documents_by_resident: dict[str, list[dict[str, str]]] = {}
    for document in documents:
        documents_by_resident.setdefault(document["resident_id"], []).append(
            {
                "kind": document["kind"],
                "url": f"/api/documents/{document['id']}",
                "preview_url": f"/api/documents/{document['id']}?inline=true",
            }
        )
    resident_data = [serialize_resident(row, documents_by_resident.get(row["id"], [])) for row in rows]
    residents_by_room: dict[str, set[int]] = {}
    for resident in resident_data:
        residents_by_room.setdefault(resident["room_id"], set()).add(resident["bed_number"])

    hostels_by_id: dict[str, dict[str, object]] = {
        row["id"]: {
            "id": row["id"],
            "name": row["name"],
            "ac_type": row["ac_type"],
            "address": decrypt_text(row["address_ciphertext"]) if row["address_ciphertext"] else "",
            "location": decrypt_text(row["location_ciphertext"]) if row["location_ciphertext"] else "",
            "owner_mobile": decrypt_text(row["owner_mobile_ciphertext"]) if row["owner_mobile_ciphertext"] else "",
            "floors": [],
            "occupied": 0,
        }
        for row in hostel_rows
    }
    floors_by_id: dict[str, dict[str, object]] = {}
    for row in floor_rows:
        floor = {
            "id": row["id"],
            "floor_number": row["floor_number"],
            "floor_type": row["floor_type"],
            "rooms": [],
        }
        floors_by_id[row["id"]] = floor
        hostel = hostels_by_id.get(row["hostel_id"])
        if hostel:
            hostel["floors"].append(floor)
    rooms: list[dict[str, object]] = []
    bookings_by_room: dict[str, sqlite3.Row] = {row["room_id_reserved"]: row for row in booking_rows}
    booking_data = [
        {
            "id": row["id"],
            "student_name": decrypt_text(row["student_name"]) if row["student_name"] else "Enquiry",
            "phone": decrypt_text(row["phone"]),
            "sharing_needed": row["sharing_needed"],
            "budget": row["budget"] / 100 if row["budget"] is not None else None,
            "visit_time": row["visit_time"],
            "reservation_expires_at": row["reservation_expires_at"],
            "room_id": row["room_id_reserved"],
            "room_number": row["room_number"],
            "hostel_id": row["hostel_id"],
            "hostel_name": row["hostel_name"],
            "floor_number": row["floor_number"],
            "monthly_rent_paise": row["monthly_rent_paise"],
        }
        for row in booking_rows
    ]
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
        reservation = bookings_by_room.get(row["id"])
        free_beds = [number for number in range(1, row["share_count"] + 1) if number not in occupied_beds]
        reserved_beds = set(free_beds) if reservation else set()
        room = {
            "id": row["id"],
            "room_number": row["room_number"],
            "share_count": row["share_count"],
            "ac_type": row["ac_type"],
            "monthly_rent_paise": row["monthly_rent_paise"],
            "monthly_rent_paise": row["monthly_rent_paise"],
            "hostel_id": row["hostel_id"],
            "hostel_name": row["hostel_name"],
            "floor_id": row["floor_id"],
            "floor_number": row["floor_number"],
            "occupied": len(occupied_beds),
            "reserved": reservation is not None,
            "reservation_name": decrypt_text(reservation["student_name"]) if reservation and reservation["student_name"] else "",
            "reservation_visit_time": reservation["visit_time"] if reservation else "",
            "available_beds": len(free_beds) - len(reserved_beds),
            "beds": [
                {"number": number, "occupied": number in occupied_beds, "reserved": number in reserved_beds}
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
            "total_hostels": len(hostel_rows),
            "occupied": len(resident_data),
            "available": sum(room["available_beds"] for room in rooms),
            "total_rooms": len(rooms),
            "rooms_open": sum(room["available_beds"] > 0 for room in rooms),
            "outstanding_paise": sum(item["amount_due_paise"] for item in resident_data),
            "paid_count": sum(item["payment_status"] == "paid" for item in resident_data),
            "unpaid_count": sum(item["payment_status"] == "unpaid" for item in resident_data),
        },
        "hostels": list(hostels_by_id.values()),
        "room_type_charges": [dict(row) for row in room_type_charge_rows],
        "rooms": rooms,
        "residents": resident_data,
        "activity": activity,
        "bookings": booking_data,
    }


@app.get("/api/residents/{resident_id}")
def resident_details(
    resident_id: str,
    staff: dict[str, str] = Depends(current_staff),
) -> dict[str, object]:
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT resident.*, room.room_number, floor.floor_number, hostel.id AS hostel_id, "
            "hostel.name AS hostel_name, "
            "(SELECT MAX(application.terms_accepted_at) FROM registration_applications application "
            "WHERE application.resident_id = resident.id) AS terms_accepted_at "
            "FROM residents resident JOIN rooms room ON room.id = resident.room_id "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE resident.id = ? AND resident.checked_out_at IS NULL AND hostel.owner_id = ?",
            (resident_id, staff["owner_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Active resident not found.")
        document_rows = connection.execute(
            "SELECT id, kind FROM documents WHERE resident_id = ? "
            "ORDER BY CASE kind WHEN 'person_photo' THEN 0 ELSE 1 END",
            (resident_id,),
        ).fetchall()
        database.write_audit(
            connection,
            staff["id"],
            "resident.details_view",
            "resident",
            resident_id,
            {},
        )

    documents = [
        {
            "kind": document["kind"],
            "url": f"/api/documents/{document['id']}",
            "preview_url": f"/api/documents/{document['id']}?inline=true",
        }
        for document in document_rows
    ]
    details = serialize_resident(row, documents)
    details["aadhaar"] = decrypt_text(row["aadhaar_ciphertext"]) if row["aadhaar_ciphertext"] else ""
    return details


@app.put("/api/hostels/{hostel_id}/room-charges")
def update_hostel_room_charges(
    hostel_id: str,
    payload: RoomTypeChargesRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat()
    saved_charges = []
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id, ac_type FROM hostels WHERE id = ? AND owner_id = ? AND active = 1",
            (hostel_id, staff["owner_id"]),
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        seen_charge_keys: set[tuple[int, str]] = set()
        for charge in payload.charges:
            ac_type = charge.ac_type or ("ac" if hostel["ac_type"] == "ac" else "non_ac")
            charge_key = (charge.share_count, ac_type)
            if charge_key in seen_charge_keys:
                raise HTTPException(status_code=422, detail="Each sharing and AC type combination can only be listed once.")
            seen_charge_keys.add(charge_key)
            if hostel["ac_type"] == "ac" and ac_type != "ac":
                raise HTTPException(status_code=422, detail="This hostel only supports AC rooms.")
            rent_paise = rent_to_paise(str(charge.monthly_rent))
            connection.execute(
                "INSERT INTO room_type_charges (hostel_id, share_count, ac_type, monthly_rent_paise, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (hostel_id, share_count, ac_type) DO UPDATE SET "
                "monthly_rent_paise = excluded.monthly_rent_paise, updated_at = excluded.updated_at",
                (hostel_id, charge.share_count, ac_type, rent_paise, now),
            )
            connection.execute(
                "UPDATE rooms SET monthly_rent_paise = ? WHERE share_count = ? AND active = 1 "
                "AND ac_type = ? AND floor_id IN (SELECT id FROM floors WHERE hostel_id = ?)",
                (rent_paise, charge.share_count, ac_type, hostel_id),
            )
            saved_charges.append({"share_count": charge.share_count, "ac_type": ac_type, "monthly_rent_paise": rent_paise})
        database.write_audit(
            connection,
            staff["id"],
            "room_type_charges.update",
            "hostel",
            hostel_id,
            {"charges": saved_charges},
        )
    return {"hostel_id": hostel_id, "charges": saved_charges}


@app.get("/api/platform/dashboard")
def platform_dashboard(account: dict[str, str] = Depends(current_platform_user)) -> dict[str, object]:
    with database.read_connection() as connection:
        summary = connection.execute(
            "SELECT (SELECT COUNT(DISTINCT owner_id) FROM hostels WHERE active = 1) AS total_clients, "
            "(SELECT COUNT(*) FROM subscription_payments WHERE status = 'received') AS subscription_received_count, "
            "(SELECT COALESCE(SUM(amount_paise), 0) FROM subscription_payments WHERE status = 'received') "
            "AS subscription_received_paise, "
            "(SELECT COUNT(*) FROM subscription_payments WHERE status = 'pending') AS subscription_pending_count, "
            "(SELECT COALESCE(SUM(amount_paise), 0) FROM subscription_payments WHERE status = 'pending') "
            "AS subscription_pending_paise"
        ).fetchone()
        client_rows = connection.execute(
            "SELECT owner.id AS owner_id, owner.username AS owner_username, hostel.id AS hostel_id, "
            "hostel.name AS hostel_name, hostel.location_ciphertext, hostel.owner_mobile_ciphertext "
            "FROM hostels hostel JOIN staff owner ON owner.id = hostel.owner_id "
            "WHERE hostel.active = 1 ORDER BY owner.username COLLATE NOCASE, hostel.name COLLATE NOCASE"
        ).fetchall()
        owner_rows = connection.execute(
            "SELECT owner.id AS owner_id, owner.username AS owner_username FROM staff owner "
            "WHERE owner.role = 'admin' AND owner.active = 1 AND EXISTS "
            "(SELECT 1 FROM hostels hostel WHERE hostel.owner_id = owner.id AND hostel.active = 1) "
            "ORDER BY owner.username COLLATE NOCASE"
        ).fetchall()
        subscription_rows = connection.execute(
            "SELECT subscription.id, subscription.owner_id, owner.username AS owner_username, "
            "subscription.billing_period, subscription.amount_paise, subscription.due_date, subscription.status, "
            "subscription.received_at FROM subscription_payments subscription "
            "JOIN staff owner ON owner.id = subscription.owner_id "
            "ORDER BY CASE subscription.status WHEN 'pending' THEN 0 ELSE 1 END, "
            "subscription.due_date, owner.username COLLATE NOCASE"
        ).fetchall()
        layout_rows = connection.execute(
            "SELECT hostel.id AS hostel_id, hostel.name AS hostel_name, hostel.ac_type, "
            "hostel.address_ciphertext, hostel.location_ciphertext, hostel.owner_mobile_ciphertext, "
            "floor.id AS floor_id, floor.floor_number, floor.floor_type, "
            "room.id AS room_id, room.room_number, room.share_count, room.ac_type, room.monthly_rent_paise "
            "FROM hostels hostel LEFT JOIN floors floor ON floor.hostel_id = hostel.id "
            "AND CAST(floor.active AS TEXT) IN ('1', 'true') "
            "LEFT JOIN rooms room ON room.floor_id = floor.id AND room.active = 1 "
            "WHERE hostel.active = 1 ORDER BY hostel.name COLLATE NOCASE, floor.floor_number, room.room_number COLLATE NOCASE"
        ).fetchall()

    hostels_by_id: dict[str, dict[str, object]] = {}
    floors_by_id: dict[str, dict[str, object]] = {}
    for row in layout_rows:
        hostel = hostels_by_id.setdefault(
            row["hostel_id"],
            {
                "id": row["hostel_id"],
                "name": row["hostel_name"],
                "ac_type": row["ac_type"],
                "address": decrypt_text(row["address_ciphertext"]) if row["address_ciphertext"] else "",
                "location": decrypt_text(row["location_ciphertext"]) if row["location_ciphertext"] else "",
                "owner_mobile": decrypt_text(row["owner_mobile_ciphertext"]) if row["owner_mobile_ciphertext"] else "",
                "floors": [],
            },
        )
        if not row["floor_id"]:
            continue
        floor = floors_by_id.get(row["floor_id"])
        if floor is None:
            floor = {
                "id": row["floor_id"],
                "floor_number": row["floor_number"],
                "floor_type": row["floor_type"],
                "rooms": [],
            }
            floors_by_id[row["floor_id"]] = floor
            hostel["floors"].append(floor)
        if row["room_id"]:
            floor["rooms"].append(
                {
                    "id": row["room_id"],
                    "room_number": row["room_number"],
                    "share_count": row["share_count"],
                    "ac_type": row["ac_type"],
                    "monthly_rent_paise": row["monthly_rent_paise"],
                    "occupied": 0,
                }
            )
    return {
        "user": account,
        "summary": dict(summary),
        "clients": [
            {
                "owner_id": row["owner_id"],
                "owner_username": row["owner_username"],
                "hostel_id": row["hostel_id"],
                "hostel_name": row["hostel_name"],
                "location": decrypt_text(row["location_ciphertext"]) if row["location_ciphertext"] else "",
                "owner_mobile": decrypt_text(row["owner_mobile_ciphertext"]) if row["owner_mobile_ciphertext"] else "",
            }
            for row in client_rows
        ],
        "owners": [dict(row) for row in owner_rows],
        "subscriptions": [dict(row) for row in subscription_rows],
        "hostels": list(hostels_by_id.values()),
    }


@app.post("/api/platform/subscriptions", status_code=201)
def create_subscription_payment(
    payload: PlatformSubscriptionRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, object]:
    owner_id = payload.owner_id.strip()
    amount_paise = amount_to_paise(str(payload.amount))
    subscription_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        owner = connection.execute(
            "SELECT id FROM staff WHERE id = ? AND role = 'admin' AND active = 1",
            (owner_id,),
        ).fetchone()
        if not owner:
            raise HTTPException(status_code=404, detail="Active hostel owner not found.")
        try:
            connection.execute(
                "INSERT INTO subscription_payments (id, owner_id, billing_period, amount_paise, due_date, status, "
                "created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
                (
                    subscription_id,
                    owner_id,
                    payload.billing_period,
                    amount_paise,
                    payload.due_date.isoformat(),
                    account["id"],
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=409, detail="A subscription payment already exists for this client and period.") from error
        database.write_audit(
            connection,
            None,
            "subscription.pending",
            "subscription_payment",
            subscription_id,
            {
                "owner_id": owner_id,
                "billing_period": payload.billing_period,
                "amount_paise": amount_paise,
                "due_date": payload.due_date.isoformat(),
                "created_by": account["username"],
            },
        )
    return {
        "id": subscription_id,
        "owner_id": owner_id,
        "billing_period": payload.billing_period,
        "amount_paise": amount_paise,
        "due_date": payload.due_date.isoformat(),
        "status": "pending",
    }


@app.patch("/api/platform/subscriptions/{subscription_id}/received")
def mark_subscription_received(
    subscription_id: str,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        subscription = connection.execute(
            "SELECT id, owner_id, status FROM subscription_payments WHERE id = ?",
            (subscription_id,),
        ).fetchone()
        if not subscription:
            raise HTTPException(status_code=404, detail="Subscription payment not found.")
        if subscription["status"] == "pending":
            connection.execute(
                "UPDATE subscription_payments SET status = 'received', received_at = ?, received_by = ?, updated_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (now, account["id"], now, subscription_id),
            )
            database.write_audit(
                connection,
                None,
                "subscription.received",
                "subscription_payment",
                subscription_id,
                {"owner_id": subscription["owner_id"], "received_by": account["username"]},
            )
    return {"id": subscription_id, "status": "received"}


@app.post("/api/platform/clients", status_code=201)
def create_platform_client(
    payload: PlatformClientRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, str]:
    owner_id = str(uuid.uuid4())
    hostel_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    owner_username = payload.owner_username.strip()
    hostel_name = payload.hostel_name.strip()
    hostel_address = payload.hostel_address.strip()
    location = payload.location.strip() if payload.location else ""
    owner_mobile = _normalize_phone(payload.owner_mobile)
    if not hostel_name:
        raise HTTPException(status_code=422, detail="Enter a hostel name.")
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO staff (id, owner_id, username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, 'admin', ?)",
                (owner_id, owner_id, owner_username, hash_password(payload.password), now),
            )
            connection.execute(
                "INSERT INTO hostels (id, owner_id, name, address_ciphertext, location_ciphertext, "
                "owner_mobile_ciphertext, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hostel_id,
                    owner_id,
                    hostel_name,
                    encrypt_text(hostel_address),
                    encrypt_text(location) if location else None,
                    encrypt_text(owner_mobile),
                    owner_id,
                    now,
                ),
            )
            database.write_audit(
                connection,
                None,
                "platform.client_create",
                "hostel",
                hostel_id,
                {"owner_username": owner_username, "hostel_name": hostel_name, "created_by": account["username"]},
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That owner username or hostel name is already in use.") from error
    return {"owner_id": owner_id, "owner_username": owner_username, "hostel_id": hostel_id, "hostel_name": hostel_name}


@app.put("/api/platform/hostels/{hostel_id}/setup")
def update_platform_hostel_setup(
    hostel_id: str,
    payload: PlatformHostelSetupRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, object]:
    floor_types = []
    if "basement" in payload.floor_types:
        floor_types.append("basement")
    if "ground" in payload.floor_types:
        floor_types.append("ground")
    floor_types.extend(["standard"] * payload.upper_floor_count)
    if "penthouse" in payload.floor_types:
        floor_types.append("penthouse")
    if not floor_types and payload.upper_floor_count == 0 or len(floor_types) > 99:
        raise HTTPException(status_code=422, detail="Choose between 1 and 99 total floors.")
    created_floors: list[dict[str, object]] = []
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id FROM hostels WHERE id = ? AND active = 1", (hostel_id,)
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        rooms_exist = connection.execute(
            "SELECT 1 FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "WHERE floor.hostel_id = ? LIMIT 1",
            (hostel_id,),
        ).fetchone()
        if rooms_exist:
            raise HTTPException(status_code=409, detail="The floor setup cannot change after rooms are added.")
        connection.execute("DELETE FROM floors WHERE hostel_id = ?", (hostel_id,))
        connection.execute("UPDATE hostels SET ac_type = ? WHERE id = ?", (payload.ac_type, hostel_id))
        for floor_number, floor_type in enumerate(floor_types, start=1):
            floor_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO floors (id, hostel_id, floor_number, floor_type, created_at) VALUES (?, ?, ?, ?, ?)",
                (floor_id, hostel_id, floor_number, floor_type, datetime.now(timezone.utc).isoformat()),
            )
            created_floors.append({"id": floor_id, "floor_number": floor_number, "floor_type": floor_type})
        database.write_audit(
            connection,
            None,
            "platform.hostel_setup",
            "hostel",
            hostel_id,
            {
                "ac_type": payload.ac_type,
                "floor_types": payload.floor_types,
                "upper_floor_count": payload.upper_floor_count,
                "updated_by": account["username"],
            },
        )
    return {"hostel_id": hostel_id, "ac_type": payload.ac_type, "floors": created_floors}


@app.post("/api/platform/hostels/{hostel_id}/floors", status_code=201)
def platform_create_floor(
    hostel_id: str,
    payload: FloorRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, object]:
    floor_id = str(uuid.uuid4())
    try:
        with database.transaction() as connection:
            hostel = connection.execute("SELECT name FROM hostels WHERE id = ? AND active = 1", (hostel_id,)).fetchone()
            if not hostel:
                raise HTTPException(status_code=404, detail="Active hostel not found.")
            connection.execute(
                "INSERT INTO floors (id, hostel_id, floor_number, floor_type, created_at) VALUES (?, ?, ?, ?, ?)",
                (floor_id, hostel_id, payload.floor_number, payload.floor_type, datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                None,
                "platform.floor_create",
                "floor",
                floor_id,
                {
                    "hostel_id": hostel_id,
                    "floor_number": payload.floor_number,
                    "floor_type": payload.floor_type,
                    "created_by": account["username"],
                },
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That floor already exists in this hostel.") from error
    return {
        "id": floor_id,
        "hostel_id": hostel_id,
        "floor_number": payload.floor_number,
        "floor_type": payload.floor_type,
    }


@app.post("/api/platform/hostels", status_code=201)
def platform_create_hostel(
    payload: PlatformHostelRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, str]:
    hostel_id = str(uuid.uuid4())
    name = payload.name.strip()
    try:
        with database.transaction() as connection:
            owner = connection.execute(
                "SELECT id FROM staff WHERE id = ? AND role = 'admin' AND active = 1",
                (payload.owner_id,),
            ).fetchone()
            if not owner:
                raise HTTPException(status_code=404, detail="Active hostel owner not found.")
            connection.execute(
                "INSERT INTO hostels (id, owner_id, name, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
                (hostel_id, owner["id"], name, owner["id"], datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                None,
                "platform.hostel_create",
                "hostel",
                hostel_id,
                {"owner_id": owner["id"], "created_by": account["username"]},
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="A hostel with that name already exists.") from error
    return {"id": hostel_id, "name": name, "owner_id": payload.owner_id}


@app.post("/api/platform/floors/{floor_id}/rooms", status_code=201)
def platform_create_room(
    floor_id: str,
    payload: RoomRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, object]:
    if payload.share_count > 4:
        raise HTTPException(status_code=422, detail="Hostel rooms can have 1 to 4 beds.")
    room_id = str(uuid.uuid4())
    room_number = payload.room_number.strip()
    try:
        with database.transaction() as connection:
            floor = connection.execute(
                "SELECT floor.floor_number, hostel.id AS hostel_id, hostel.name AS hostel_name, hostel.ac_type "
                "FROM floors floor JOIN hostels hostel ON hostel.id = floor.hostel_id "
                "WHERE floor.id = ? AND CAST(floor.active AS TEXT) IN ('1', 'true') AND hostel.active = 1",
                (floor_id,),
            ).fetchone()
            if not floor:
                raise HTTPException(status_code=404, detail="Floor not found.")
            ac_type = payload.ac_type or ("ac" if floor["ac_type"] == "ac" else "non_ac")
            if floor["ac_type"] == "ac" and ac_type != "ac":
                raise HTTPException(status_code=422, detail="This hostel only supports AC rooms.")
            rent_paise = room_type_charge_or_fallback(
                connection,
                floor["hostel_id"],
                payload.share_count,
                ac_type,
                rent_to_paise(str(payload.monthly_rent)),
            )
            connection.execute(
                "INSERT INTO rooms (id, floor_id, room_number, share_count, ac_type, monthly_rent_paise, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (room_id, floor_id, room_number, payload.share_count, ac_type, rent_paise, datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                None,
                "platform.room_create",
                "room",
                room_id,
                {"hostel_id": floor["hostel_id"], "room_number": room_number, "share_count": payload.share_count, "ac_type": ac_type, "created_by": account["username"]},
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That room number already exists on this floor.") from error
    return {
        "id": room_id,
        "floor_id": floor_id,
        "room_number": room_number,
        "share_count": payload.share_count,
        "ac_type": ac_type,
        "monthly_rent_paise": rent_paise,
    }


@app.delete("/api/platform/floors/{floor_id}")
def delete_platform_floor(
    floor_id: str,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        floor = connection.execute(
            "SELECT floor.floor_number, floor.floor_type, hostel.name AS hostel_name "
            "FROM floors floor JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE floor.id = ? AND CAST(floor.active AS TEXT) IN ('1', 'true') AND hostel.active = 1",
            (floor_id,),
        ).fetchone()
        if not floor:
            raise HTTPException(status_code=404, detail="Active floor not found.")
        occupied = connection.execute(
            "SELECT COUNT(*) FROM residents resident JOIN rooms room ON room.id = resident.room_id "
            "WHERE room.floor_id = ? AND resident.checked_out_at IS NULL",
            (floor_id,),
        ).fetchone()[0]
        if occupied:
            raise HTTPException(status_code=409, detail="Check out or move residents before deleting this floor.")
        reserved = connection.execute(
            "SELECT COUNT(*) FROM bookings booking JOIN rooms room ON room.id = booking.room_id_reserved "
            "WHERE room.floor_id = ? AND booking.status = 'visit_booked' AND booking.cancelled_at IS NULL "
            "AND booking.reservation_expires_at > ?",
            (floor_id, now),
        ).fetchone()[0]
        if reserved:
            raise HTTPException(status_code=409, detail="Cancel or expire reservations before deleting this floor.")
        room_count = connection.execute(
            "SELECT COUNT(*) FROM rooms WHERE floor_id = ? AND active = 1", (floor_id,)
        ).fetchone()[0]
        connection.execute("UPDATE rooms SET active = 0 WHERE floor_id = ? AND active = 1", (floor_id,))
        connection.execute("UPDATE floors SET active = FALSE WHERE id = ?", (floor_id,))
        database.write_audit(
            connection,
            None,
            "platform.floor_delete",
            "floor",
            floor_id,
            {
                "hostel_name": floor["hostel_name"],
                "floor_number": floor["floor_number"],
                "floor_type": floor["floor_type"],
                "rooms_archived": room_count,
                "history_retained": True,
                "deleted_by": account["username"],
            },
        )
    return {"status": "deleted", "floor_number": floor["floor_number"], "rooms_archived": room_count}


@app.post("/api/hostels", status_code=201)
def create_hostel(
    payload: PlatformHostelRequest,
    account: dict[str, str] = Depends(require_platform_write),
) -> dict[str, str]:
    return platform_create_hostel(payload, account)


@app.put("/api/hostels/{hostel_id}/setup")
def update_owner_hostel_setup(
    hostel_id: str,
    payload: PlatformHostelSetupRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, object]:
    floor_types = []
    if "basement" in payload.floor_types:
        floor_types.append("basement")
    if "ground" in payload.floor_types:
        floor_types.append("ground")
    floor_types.extend(["standard"] * payload.upper_floor_count)
    if "penthouse" in payload.floor_types:
        floor_types.append("penthouse")
    if not floor_types or len(floor_types) > 99:
        raise HTTPException(status_code=422, detail="Choose between 1 and 99 total floors.")

    created_floors: list[dict[str, object]] = []
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id FROM hostels WHERE id = ? AND active = 1 AND owner_id = ?",
            (hostel_id, staff["owner_id"]),
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        rooms_exist = connection.execute(
            "SELECT 1 FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "WHERE floor.hostel_id = ? AND room.active = 1 LIMIT 1",
            (hostel_id,),
        ).fetchone()
        if rooms_exist:
            raise HTTPException(status_code=409, detail="Remove existing rooms before replacing the floor setup.")
        connection.execute(
            "UPDATE floors SET active = FALSE WHERE hostel_id = ? "
            "AND CAST(active AS TEXT) IN ('1', 'true')",
            (hostel_id,),
        )
        connection.execute("UPDATE hostels SET ac_type = ? WHERE id = ?", (payload.ac_type, hostel_id))
        for floor_number, floor_type in enumerate(floor_types, start=1):
            floor_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO floors (id, hostel_id, floor_number, floor_type, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (floor_id, hostel_id, floor_number, floor_type, datetime.now(timezone.utc).isoformat()),
            )
            created_floors.append({"id": floor_id, "floor_number": floor_number, "floor_type": floor_type})
        database.write_audit(
            connection,
            staff["id"],
            "hostel.layout_setup",
            "hostel",
            hostel_id,
            {"floor_count": len(floor_types), "ac_type": payload.ac_type},
        )
    return {"hostel_id": hostel_id, "ac_type": payload.ac_type, "floors": created_floors}


@app.delete("/api/hostels/{hostel_id}")
def delete_hostel(hostel_id: str, staff: dict[str, str] = Depends(require_platform_write)) -> dict[str, str]:
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id, name FROM hostels WHERE id = ? AND active = 1",
            (hostel_id,),
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
        reserved = connection.execute(
            "SELECT COUNT(*) FROM bookings WHERE hostel_id = ? AND status = 'visit_booked' "
            "AND cancelled_at IS NULL AND reservation_expires_at > ?",
            (hostel_id, datetime.now(timezone.utc).isoformat()),
        ).fetchone()[0]
        if reserved:
            raise HTTPException(status_code=409, detail="Cancel or expire pending room reservations before deleting this hostel.")
        connection.execute(
            "UPDATE rooms SET active = 0 WHERE floor_id IN (SELECT id FROM floors WHERE hostel_id = ?)",
            (hostel_id,),
        )
        connection.execute("UPDATE hostels SET active = 0 WHERE id = ?", (hostel_id,))
        database.write_audit(
            connection,
            None,
            "hostel.delete",
            "hostel",
            hostel_id,
            {"name": hostel["name"], "history_retained": True, "deleted_by": staff["username"]},
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
                "INSERT INTO floors (id, hostel_id, floor_number, floor_type, created_at) VALUES (?, ?, ?, ?, ?)",
                (floor_id, hostel_id, payload.floor_number, payload.floor_type, datetime.now(timezone.utc).isoformat()),
            )
            database.write_audit(
                connection,
                staff["id"],
                "floor.create",
                "floor",
                floor_id,
                {
                    "hostel_id": hostel_id,
                    "floor_number": payload.floor_number,
                    "floor_type": payload.floor_type,
                    "created_by": staff["username"],
                },
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That floor already exists in this hostel.") from error
    return {
        "id": floor_id,
        "hostel_id": hostel_id,
        "floor_number": payload.floor_number,
        "floor_type": payload.floor_type,
        "name": floor_name(payload.floor_number),
    }


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
                "SELECT floor_number, hostel.id AS hostel_id, hostel.name AS hostel_name, hostel.ac_type "
                "FROM floors JOIN hostels hostel ON hostel.id = floors.hostel_id "
                "WHERE floors.id = ? AND CAST(floors.active AS TEXT) IN ('1', 'true') "
                "AND hostel.active = 1 AND hostel.owner_id = ?",
                (floor_id, staff["owner_id"]),
            ).fetchone()
            if not floor:
                raise HTTPException(status_code=404, detail="Floor not found.")
            ac_type = payload.ac_type or ("ac" if floor["ac_type"] == "ac" else "non_ac")
            if floor["ac_type"] == "ac" and ac_type != "ac":
                raise HTTPException(status_code=422, detail="This hostel only supports AC rooms.")
            rent_paise = room_type_charge_or_fallback(
                connection,
                floor["hostel_id"],
                payload.share_count,
                ac_type,
                rent_to_paise(str(payload.monthly_rent)),
            )
            connection.execute(
                "INSERT INTO rooms (id, floor_id, room_number, share_count, ac_type, monthly_rent_paise, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    room_id,
                    floor_id,
                    room_number,
                    payload.share_count,
                    ac_type,
                    rent_paise,
                    datetime.now(timezone.utc).isoformat(),
                ),
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
                    "ac_type": ac_type,
                    "floor_number": floor["floor_number"],
                    "hostel_name": floor["hostel_name"],
                    "created_by": staff["username"],
                },
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That room number already exists on this floor.") from error
    return {
        "id": room_id,
        "floor_id": floor_id,
        "room_number": room_number,
        "share_count": payload.share_count,
        "ac_type": ac_type,
        "monthly_rent_paise": rent_paise,
        "floor_number": floor["floor_number"],
        "hostel_id": floor["hostel_id"],
        "hostel_name": floor["hostel_name"],
    }


@app.delete("/api/floors/{floor_id}")
def delete_owner_floor(floor_id: str, staff: dict[str, str] = Depends(require_admin)) -> dict[str, object]:
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        floor = connection.execute(
            "SELECT floor.floor_number, floor.floor_type, hostel.name AS hostel_name "
            "FROM floors floor JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE floor.id = ? AND CAST(floor.active AS TEXT) IN ('1', 'true') "
            "AND hostel.active = 1 AND hostel.owner_id = ?",
            (floor_id, staff["owner_id"]),
        ).fetchone()
        if not floor:
            raise HTTPException(status_code=404, detail="Active floor not found.")
        occupied = connection.execute(
            "SELECT COUNT(*) FROM residents resident JOIN rooms room ON room.id = resident.room_id "
            "WHERE room.floor_id = ? AND resident.checked_out_at IS NULL",
            (floor_id,),
        ).fetchone()[0]
        if occupied:
            raise HTTPException(status_code=409, detail="Check out or move residents before deleting this floor.")
        reserved = connection.execute(
            "SELECT COUNT(*) FROM bookings booking JOIN rooms room ON room.id = booking.room_id_reserved "
            "WHERE room.floor_id = ? AND booking.status = 'visit_booked' AND booking.cancelled_at IS NULL "
            "AND booking.reservation_expires_at > ?",
            (floor_id, now),
        ).fetchone()[0]
        if reserved:
            raise HTTPException(status_code=409, detail="Cancel or expire reservations before deleting this floor.")
        room_count = connection.execute(
            "SELECT COUNT(*) FROM rooms WHERE floor_id = ? AND active = 1", (floor_id,)
        ).fetchone()[0]
        connection.execute("UPDATE rooms SET active = 0 WHERE floor_id = ? AND active = 1", (floor_id,))
        connection.execute("UPDATE floors SET active = FALSE WHERE id = ?", (floor_id,))
        database.write_audit(
            connection,
            staff["id"],
            "floor.delete",
            "floor",
            floor_id,
            {
                "hostel_name": floor["hostel_name"],
                "floor_number": floor["floor_number"],
                "floor_type": floor["floor_type"],
                "rooms_archived": room_count,
                "history_retained": True,
            },
        )
    return {"status": "deleted", "floor_number": floor["floor_number"], "rooms_archived": room_count}


def floor_name(floor_number: int) -> str:
    suffix = "th" if 10 <= floor_number % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(floor_number % 10, "th")
    return f"{floor_number}{suffix} Floor"


def _room_vacancy_rows(
    connection: sqlite3.Connection | database.PostgresConnection,
    hostel_id: str | None = None,
    owner_id: str | None = None,
) -> list[sqlite3.Row]:
    now = datetime.now(timezone.utc).isoformat()
    conditions = ["room.active = 1", "hostel.active = 1"]
    parameters: list[object] = [now]
    if hostel_id:
        conditions.append("hostel.id = ?")
        parameters.append(hostel_id)
    if owner_id:
        conditions.append("hostel.owner_id = ?")
        parameters.append(owner_id)
    return connection.execute(
        "SELECT room.id, room.room_number, room.share_count, room.monthly_rent_paise, "
        "floor.floor_number, hostel.id AS hostel_id, hostel.name AS hostel_name, hostel.owner_id, "
        "(SELECT COUNT(*) FROM residents resident WHERE resident.room_id = room.id "
        "AND resident.checked_out_at IS NULL) AS occupied, "
        "(SELECT COUNT(*) FROM bookings booking WHERE booking.room_id_reserved = room.id "
        "AND booking.status = 'visit_booked' AND booking.cancelled_at IS NULL "
        "AND booking.reservation_expires_at > ?) AS reserved_count "
        "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
        "JOIN hostels hostel ON hostel.id = floor.hostel_id WHERE "
        + " AND ".join(conditions)
        + " ORDER BY hostel.name COLLATE NOCASE, floor.floor_number, room.room_number COLLATE NOCASE",
        tuple(parameters),
    ).fetchall()


def _vacancy_payload(
    connection: sqlite3.Connection | database.PostgresConnection,
    hostel_id: str | None = None,
    owner_id: str | None = None,
) -> dict[str, object]:
    rows = _room_vacancy_rows(connection, hostel_id, owner_id)
    vacant = [row for row in rows if row["occupied"] < row["share_count"] and not row["reserved_count"]]
    vacant_list = [
        {
            "room_id": row["id"],
            "room_no": row["room_number"],
            "sharing_type": f"{row['share_count']} sharing",
            "share_count": row["share_count"],
            "rent": row["monthly_rent_paise"] / 100 if row["monthly_rent_paise"] else None,
            "floor": row["floor_number"],
            "hostel_id": row["hostel_id"],
            "hostel_name": row["hostel_name"],
        }
        for row in vacant
    ]
    return {"total_rooms": len(rows), "vacant_count": len(vacant_list), "vacant_list": vacant_list}


def _normalize_phone(phone: str) -> str:
    normalized = re.sub(r"[\s().-]", "", phone)
    if normalized.startswith("00"):
        normalized = f"+{normalized[2:]}"
    elif not normalized.startswith("+"):
        if re.fullmatch(r"[0-9]{10}", normalized):
            normalized = f"+91{normalized}"
        elif re.fullmatch(r"0[0-9]{10}", normalized):
            normalized = f"+91{normalized[1:]}"
        else:
            normalized = f"+{normalized}"
    if not re.fullmatch(r"\+[0-9]{10,15}", normalized):
        raise HTTPException(status_code=422, detail="Enter a valid phone number.")
    return normalized


def _validated_purpose_of_stay(category: str, other_details: str) -> str:
    if category in {"Work", "Studies"}:
        if other_details:
            raise HTTPException(status_code=422, detail="Only enter other details when purpose is Other.")
        return category
    if category == "Other":
        if not other_details:
            raise HTTPException(status_code=422, detail="Describe the purpose of stay.")
        return f"Other: {other_details}"
    if category or other_details:
        raise HTTPException(status_code=422, detail="Choose Work, Studies, or Other as the purpose of stay.")
    return ""


def _whatsapp_recipient_number(phone: str) -> str:
    digits = re.sub(r"\D", "", _normalize_phone(phone))
    if len(digits) == 10:
        return f"91{digits}"
    if digits.startswith("0") and len(digits) == 11:
        return f"91{digits[1:]}"
    return digits


def _reserve_booking(
    *,
    name: str,
    phone: str,
    sharing_needed: int | None,
    budget: Decimal | None,
    visit_time: str,
    hostel_id: str | None = None,
    language: str = "en",
    existing_booking_id: str | None = None,
    staff: dict[str, str] | None = None,
) -> dict[str, object]:
    normalized_phone = _normalize_phone(phone)
    clean_name = name.strip()
    clean_visit_time = visit_time.strip()
    if not clean_name or not clean_visit_time:
        raise HTTPException(status_code=422, detail="A name and visit time are required.")
    budget_paise = amount_to_paise(str(budget)) if budget is not None else None
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    expires_at = (now + timedelta(hours=24)).isoformat()
    with database.transaction() as connection:
        connection.execute(
            "UPDATE bookings SET status = 'enquiry', room_id_reserved = NULL, reservation_expires_at = NULL, "
            "updated_at = ? WHERE status = 'visit_booked' AND cancelled_at IS NULL "
            "AND reservation_expires_at <= ?",
            (now_text, now_text),
        )
        if existing_booking_id:
            existing = connection.execute(
                "SELECT id, owner_id, hostel_id FROM bookings WHERE id = ? AND status = 'enquiry' "
                "AND cancelled_at IS NULL",
                (existing_booking_id,),
            ).fetchone()
            if not existing:
                raise HTTPException(status_code=409, detail="This enquiry is no longer available to book.")
            hostel_id = existing["hostel_id"]
        elif not hostel_id:
            active_hostels = connection.execute(
                "SELECT id FROM hostels WHERE active = 1 ORDER BY name COLLATE NOCASE LIMIT 2"
            ).fetchall()
            if len(active_hostels) > 1:
                raise HTTPException(status_code=422, detail="Choose a hostel using hostel_id before creating a booking.")
            if active_hostels:
                hostel_id = active_hostels[0]["id"]
        candidates = _room_vacancy_rows(connection, hostel_id)
        candidates = [
            row for row in candidates
            if row["occupied"] < row["share_count"] and not row["reserved_count"]
            and (sharing_needed is None or row["share_count"] == sharing_needed)
            and (
                budget_paise is None
                or (row["monthly_rent_paise"] > 0 and row["monthly_rent_paise"] <= budget_paise)
            )
        ]
        if not candidates:
            raise HTTPException(status_code=409, detail="No matching vacant room is available right now.")
        room = candidates[0]
        booking_id = existing_booking_id or str(uuid.uuid4())
        values = (
            encrypt_text(clean_name),
            encrypt_text(normalized_phone),
            hash_address(normalized_phone),
            sharing_needed,
            budget_paise,
            "visit_booked",
            clean_visit_time,
            room["id"],
            expires_at,
            language,
            staff["id"] if staff else None,
            staff["id"] if staff else None,
            now_text,
            booking_id,
        )
        try:
            if existing_booking_id:
                connection.execute(
                    "UPDATE bookings SET student_name = ?, phone = ?, phone_hash = ?, sharing_needed = ?, budget = ?, "
                    "status = ?, visit_time = ?, room_id_reserved = ?, reservation_expires_at = ?, language = ?, "
                    "created_by = COALESCE(created_by, ?), updated_at = ? WHERE id = ?",
                    values[:10] + values[10:11] + (now_text, booking_id),
                )
            else:
                connection.execute(
                    "INSERT INTO bookings (id, owner_id, hostel_id, student_name, phone, phone_hash, sharing_needed, "
                    "budget, status, visit_time, room_id_reserved, reservation_expires_at, language, created_by, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        booking_id,
                        room["owner_id"],
                        room["hostel_id"],
                        encrypt_text(clean_name),
                        encrypt_text(normalized_phone),
                        hash_address(normalized_phone),
                        sharing_needed,
                        budget_paise,
                        "visit_booked",
                        clean_visit_time,
                        room["id"],
                        expires_at,
                        language,
                        staff["id"] if staff else None,
                        now_text,
                        now_text,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=409, detail="That room was just reserved. Please choose another room.") from error
        database.write_audit(
            connection,
            staff["id"] if staff else None,
            "booking.create",
            "booking",
            booking_id,
            {"room_id": room["id"], "hostel_id": room["hostel_id"], "visit_time": clean_visit_time},
        )
    return {
        "booking_id": booking_id,
        "room_id": room["id"],
        "room_no": room["room_number"],
        "hostel_id": room["hostel_id"],
        "hostel_name": room["hostel_name"],
        "reservation_expires_at": expires_at,
    }


@app.get("/api/vacancy/live")
def live_vacancy(hostel_id: str | None = None) -> dict[str, object]:
    with database.read_connection() as connection:
        if not hostel_id:
            active_hostels = connection.execute(
                "SELECT id FROM hostels WHERE active = 1 ORDER BY name COLLATE NOCASE LIMIT 2"
            ).fetchall()
            if len(active_hostels) > 1:
                raise HTTPException(status_code=422, detail="Specify hostel_id to view one hostel's live vacancy.")
            if active_hostels:
                hostel_id = active_hostels[0]["id"]
        if hostel_id and not connection.execute(
            "SELECT 1 FROM hostels WHERE id = ? AND active = 1", (hostel_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        return _vacancy_payload(connection, hostel_id)


@app.post("/api/bookings/create", status_code=201)
def create_booking(payload: BookingCreateRequest) -> dict[str, object]:
    return _reserve_booking(
        name=payload.name,
        phone=payload.phone,
        sharing_needed=payload.sharing_needed,
        budget=payload.budget,
        visit_time=payload.visit_time,
        hostel_id=payload.hostel_id,
    )


@app.get("/api/bookings")
def list_bookings(staff: dict[str, str] = Depends(current_staff)) -> list[dict[str, object]]:
    with database.read_connection() as connection:
        now = datetime.now(timezone.utc).isoformat()
        rows = connection.execute(
            "SELECT booking.*, room.room_number, room.monthly_rent_paise, floor.floor_number, "
            "hostel.name AS hostel_name FROM bookings booking "
            "JOIN rooms room ON room.id = booking.room_id_reserved "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE booking.owner_id = ? AND booking.status = 'visit_booked' AND booking.cancelled_at IS NULL "
            "AND booking.reservation_expires_at > ? ORDER BY booking.visit_time, booking.created_at",
            (staff["owner_id"], now),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "student_name": decrypt_text(row["student_name"]),
            "phone": decrypt_text(row["phone"]),
            "sharing_needed": row["sharing_needed"],
            "budget": row["budget"] / 100 if row["budget"] is not None else None,
            "visit_time": row["visit_time"],
            "reservation_expires_at": row["reservation_expires_at"],
            "room_id": row["room_id_reserved"],
            "room_number": row["room_number"],
            "hostel_name": row["hostel_name"],
            "floor_number": row["floor_number"],
            "monthly_rent_paise": row["monthly_rent_paise"],
        }
        for row in rows
    ]


@app.post("/api/bookings/confirm/{booking_id}")
def confirm_booking(
    booking_id: str,
    staff: dict[str, str] = Depends(require_write),
) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    joined = now.date()
    payment_due = due_date_after_one_month(joined)
    resident_id = str(uuid.uuid4())
    with database.transaction() as connection:
        booking = connection.execute(
            "SELECT booking.*, room.share_count, room.monthly_rent_paise, room.room_number, "
            "hostel.name AS hostel_name, floor.floor_number FROM bookings booking "
            "JOIN rooms room ON room.id = booking.room_id_reserved "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE booking.id = ? AND booking.owner_id = ? AND booking.status = 'visit_booked' "
            "AND booking.cancelled_at IS NULL AND booking.reservation_expires_at > ? AND room.active = 1 "
            "AND hostel.active = 1",
            (booking_id, staff["owner_id"], now.isoformat()),
        ).fetchone()
        if not booking:
            raise HTTPException(status_code=404, detail="Active booking not found or its reservation expired.")
        bed_rows = connection.execute(
            "SELECT bed_number FROM residents WHERE room_id = ? AND checked_out_at IS NULL ORDER BY bed_number",
            (booking["room_id_reserved"],),
        ).fetchall()
        occupied_beds = {row["bed_number"] for row in bed_rows}
        bed_number = next(
            (number for number in range(1, booking["share_count"] + 1) if number not in occupied_beds),
            None,
        )
        if bed_number is None:
            raise HTTPException(status_code=409, detail="No bed remains available in the reserved room.")
        other_booking = connection.execute(
            "SELECT 1 FROM bookings WHERE room_id_reserved = ? AND id <> ? AND status = 'visit_booked' "
            "AND cancelled_at IS NULL AND reservation_expires_at > ? LIMIT 1",
            (booking["room_id_reserved"], booking_id, now.isoformat()),
        ).fetchone()
        if other_booking:
            raise HTTPException(status_code=409, detail="Another active booking already holds this room.")
        rent_paise = booking["monthly_rent_paise"]
        connection.execute(
            "INSERT INTO residents (id, name_ciphertext, mobile_ciphertext, aadhaar_ciphertext, room_id, "
            "bed_number, joining_date, payment_due_date, payment_status, amount_due_paise, created_by, created_at) "
            "VALUES (?, ?, ?, NULL, ?, ?, ?, ?, 'unpaid', ?, ?, ?)",
            (
                resident_id,
                booking["student_name"],
                booking["phone"],
                booking["room_id_reserved"],
                bed_number,
                joined.isoformat(),
                payment_due.isoformat(),
                rent_paise,
                staff["id"],
                now.isoformat(),
            ),
        )
        connection.execute(
            "UPDATE bookings SET status = 'joined', reservation_expires_at = NULL, resident_id = ?, "
            "confirmed_by = ?, updated_at = ? WHERE id = ?",
            (resident_id, staff["id"], now.isoformat(), booking_id),
        )
        database.write_audit(
            connection,
            staff["id"],
            "resident.checkin",
            "resident",
            resident_id,
            {
                "room": booking["room_number"],
                "room_id": booking["room_id_reserved"],
                "room_number": booking["room_number"],
                "hostel_name": booking["hostel_name"],
                "floor_number": booking["floor_number"],
                "bed_number": bed_number,
                "payment_status": "unpaid",
                "amount_due_paise": rent_paise,
                "payment_due_date": payment_due.isoformat(),
            },
        )
        database.write_audit(connection, staff["id"], "booking.joined", "booking", booking_id)
    return {"booking_id": booking_id, "resident_id": resident_id}


@app.delete("/api/bookings/{booking_id}")
def cancel_booking(
    booking_id: str,
    staff: dict[str, str] = Depends(require_write),
) -> dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        booking = connection.execute(
            "SELECT id FROM bookings WHERE id = ? AND owner_id = ? AND status = 'visit_booked' "
            "AND cancelled_at IS NULL",
            (booking_id, staff["owner_id"]),
        ).fetchone()
        if not booking:
            raise HTTPException(status_code=404, detail="Active booking not found.")
        connection.execute(
            "UPDATE bookings SET status = 'enquiry', cancelled_at = ?, room_id_reserved = NULL, "
            "reservation_expires_at = NULL, updated_at = ? WHERE id = ?",
            (now, now, booking_id),
        )
        database.write_audit(connection, staff["id"], "booking.cancel", "booking", booking_id)
    return {"status": "cancelled"}


@app.patch("/api/rooms/{room_id}/rent")
def update_room_rent(
    room_id: str,
    payload: RoomRentRequest,
    staff: dict[str, str] = Depends(require_platform_write),
) -> dict[str, int | str]:
    rent_paise = rent_to_paise(str(payload.monthly_rent))
    with database.transaction() as connection:
        room = connection.execute(
            "SELECT room.id, room.room_number FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id WHERE room.id = ? AND room.active = 1 "
            "AND hostel.active = 1",
            (room_id,),
        ).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="Active room not found.")
        connection.execute("UPDATE rooms SET monthly_rent_paise = ? WHERE id = ?", (rent_paise, room_id))
        database.write_audit(
            connection,
            None,
            "room.rent_updated",
            "room",
            room_id,
            {"monthly_rent_paise": rent_paise, "updated_by": staff["username"]},
        )
    return {"room_id": room_id, "room_number": room["room_number"], "monthly_rent_paise": rent_paise}


@app.get("/api/qr/{hostel_id}")
def vacancy_qr(
    hostel_id: str,
    download: bool = False,
    staff: dict[str, str] = Depends(current_staff),
) -> Response:
    if staff["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    if not config.WHATSAPP_BUSINESS_NUMBER or not config.WHATSAPP_BUSINESS_NUMBER.isdigit():
        raise HTTPException(status_code=503, detail="Configure WHATSAPP_BUSINESS_NUMBER to generate the vacancy QR.")
    with database.read_connection() as connection:
        hostel = connection.execute(
            "SELECT id FROM hostels WHERE id = ? AND owner_id = ? AND active = 1",
            (hostel_id, staff["owner_id"]),
        ).fetchone()
    if not hostel:
        raise HTTPException(status_code=404, detail="Active hostel not found.")
    import qrcode

    message = f"Hi CHECK VACANCY HOSTELID_{hostel_id}"
    qr_url = f"https://wa.me/{config.WHATSAPP_BUSINESS_NUMBER}?text={quote(message)}"
    image = qrcode.make(qr_url, box_size=12, border=2)
    output = BytesIO()
    image.save(output, format="PNG")
    headers = {"Cache-Control": "private, max-age=300"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="hostel-{hostel_id}.png"'
    return Response(content=output.getvalue(), media_type="image/png", headers=headers)


def _detect_message_language(message: str) -> str:
    if re.search(r"[\u0c00-\u0c7f]", message):
        return "te"
    if re.search(r"[\u0900-\u097f]", message):
        return "hi"
    if re.search(r"\b(khali|chahiye|batao|kitna|hai|mera|naam|karna|room|ke liye)\b", message, re.I):
        return "hinglish"
    return "en"


WHATSAPP_COPY = {
    "en": {
        "vacancy": "{hostel}: {count} rooms are vacant: {rooms}. Tell me your sharing preference and monthly budget.",
        "options": "{hostel}: these rooms match: {rooms}. Send your name and preferred visit time to reserve one.",
        "ask_preferences": "How many sharing do you need, and what is your monthly budget in rupees?",
        "ask_name_time": "Send your name and preferred visit time to reserve a room.",
        "ask_name": "Please send your name so I can book the visit.",
        "ask_time": "What time would you like to visit?",
        "no_rooms": "There are no matching vacant rooms right now. Please check again later.",
        "choose_hostel": "Please scan the vacancy QR at your hostel so I can show its rooms.",
        "booked": "Booking done for {time}, Room {room} reserved for 24 hours.",
    },
    "hinglish": {
        "vacancy": "{hostel}: {count} rooms vacant hain: {rooms}. Budget aur sharing batao.",
        "options": "{hostel}: ye rooms available hain: {rooms}. Reserve karne ke liye apna naam aur visit time bhejo.",
        "ask_preferences": "Kitni sharing chahiye aur monthly budget kitna hai?",
        "ask_name_time": "Room reserve karne ke liye apna naam aur visit time bhejo.",
        "ask_name": "Booking ke liye apna naam bhejo.",
        "ask_time": "Aap kis time visit karna chahenge?",
        "no_rooms": "Abhi matching vacant room nahi hai. Thodi der baad phir check karein.",
        "choose_hostel": "Apne hostel ka vacancy QR scan karein, phir main usi hostel ke rooms dikhaunga.",
        "booked": "{time} ke liye booking done, Room {room} 24 hours ke liye reserved hai.",
    },
    "hi": {
        "vacancy": "{hostel}: {count} कमरे खाली हैं: {rooms}। अपनी sharing और monthly budget बताइए।",
        "options": "{hostel}: ये कमरे उपलब्ध हैं: {rooms}। बुकिंग के लिए अपना नाम और आने का समय भेजें।",
        "ask_preferences": "कितनी sharing चाहिए और आपका monthly budget कितना है?",
        "ask_name_time": "कमरा reserve करने के लिए अपना नाम और आने का समय भेजें।",
        "ask_name": "बुकिंग के लिए अपना नाम भेजें।",
        "ask_time": "आप किस समय आना चाहेंगे?",
        "no_rooms": "अभी matching कमरा खाली नहीं है। कृपया थोड़ी देर बाद फिर पूछें।",
        "choose_hostel": "अपने hostel का vacancy QR scan करें, ताकि मैं उसी hostel के कमरे दिखा सकूँ।",
        "booked": "{time} के लिए booking हो गई। कमरा {room} 24 घंटे के लिए reserve है।",
    },
    "te": {
        "vacancy": "{hostel}: {count} గదులు ఖాళీగా ఉన్నాయి: {rooms}. మీ sharing మరియు నెలవారీ budget చెప్పండి.",
        "options": "{hostel}: సరిపోయే గదులు: {rooms}. బుక్ చేయడానికి మీ పేరు, రావాల్సిన సమయం పంపండి.",
        "ask_preferences": "ఎన్ని sharing కావాలి? మీ నెలవారీ budget ఎంత?",
        "ask_name_time": "గదిని reserve చేయడానికి మీ పేరు, రావాల్సిన సమయం పంపండి.",
        "ask_name": "బుకింగ్ కోసం మీ పేరు పంపండి.",
        "ask_time": "మీరు ఏ సమయంలో రావాలనుకుంటున్నారు?",
        "no_rooms": "ప్రస్తుతం సరిపోయే ఖాళీ గది లేదు. కొంతసేపటి తర్వాత మళ్లీ చూడండి.",
        "choose_hostel": "ఆ హాస్టల్ గదుల వివరాల కోసం గేట్ వద్ద ఉన్న vacancy QR స్కాన్ చేయండి.",
        "booked": "{time} కోసం బుకింగ్ పూర్తైంది. గది {room} 24 గంటలు reserve చేయబడింది.",
    },
}


def _whatsapp_text(language: str, key: str, **values: object) -> str:
    return WHATSAPP_COPY[language][key].format(**values)


def _parse_sharing(message: str) -> int | None:
    match = re.search(r"\b(1\d|\d)\s*(?:sharing|share|seater|bed|sharing-ல?)\b", message, re.I)
    return int(match.group(1)) if match else None


def _parse_budget(message: str) -> Decimal | None:
    patterns = (
        r"(?:₹|rs\.?|rupees?|budget\s*(?:is|:)?|under|upto|up to)\s*([\d,]+(?:\.\d+)?)\s*(k)?",
        r"\b([\d.]+)\s*k\b",
        r"\b([\d,]{4,7})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, message, re.I)
        if match:
            try:
                amount = Decimal(match.group(1).replace(",", ""))
                if len(match.groups()) > 1 and match.group(2):
                    amount *= 1000
                if Decimal("0") < amount <= Decimal("1000000"):
                    return amount
            except InvalidOperation:
                pass
    return None


def _parse_booking_name(message: str) -> str | None:
    match = re.search(
        r"(?:my name is|i am|name(?: is)?\s*[:=-]?|mera naam|naam hai|मेरा नाम|मेरा नाम है|నా పేరు)\s+(.+?)"
        r"(?=,|\.|!|\b(?:visit|at|time|today|tomorrow|kal)\b|$)",
        message,
        re.I,
    )
    if match:
        name = re.sub(r"\s+(?:and|visit)$", "", match.group(1).strip(), flags=re.I)
        return name[:80] or None
    time_match = re.search(r"\b(?:at\s*)?\d{1,2}(?::\d{2})?\s*(?:am|pm)\b|\b\d{1,2}:\d{2}\b", message, re.I)
    if time_match:
        candidate = message[:time_match.start()].strip(" ,.-")
        candidate = re.sub(r"^(?:name\s*[:=-]?|i am)\s*", "", candidate, flags=re.I)
        if 1 <= len(candidate.split()) <= 3 and not re.search(
            r"\b(?:budget|sharing|share|room|visit|today|tomorrow|at|and|my|want|need)\b|\d",
            candidate,
            re.I,
        ):
            return candidate[:80]
    return None


def _parse_visit_time(message: str) -> str | None:
    match = re.search(r"\b(?:at\s*)?(\d{1,2}(?::\d{2})?\s*(?:am|pm))\b", message, re.I)
    if not match:
        match = re.search(r"\b(?:at\s*)?(\d{1,2}:\d{2})\b", message, re.I)
    if not match:
        match = re.search(r"\b(\d{1,2})\s*(?:baje|గంటలకు)\b", message, re.I)
    return match.group(1).strip() if match else None


def _upsert_whatsapp_enquiry(
    phone: str,
    hostel_id: str,
    language: str,
    sharing_needed: int | None,
    budget: Decimal | None,
    name: str | None,
    visit_time: str | None,
) -> sqlite3.Row:
    normalized_phone = _normalize_phone(phone)
    phone_hash = hash_address(normalized_phone)
    budget_paise = amount_to_paise(str(budget)) if budget is not None else None
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id, owner_id FROM hostels WHERE id = ? AND active = 1", (hostel_id,)
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        enquiry = connection.execute(
            "SELECT id FROM bookings WHERE phone_hash = ? AND hostel_id = ? AND status = 'enquiry' "
            "AND cancelled_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (phone_hash, hostel_id),
        ).fetchone()
        if enquiry:
            connection.execute(
                "UPDATE bookings SET student_name = COALESCE(?, student_name), sharing_needed = COALESCE(?, sharing_needed), "
                "budget = COALESCE(?, budget), visit_time = COALESCE(?, visit_time), language = ?, updated_at = ? "
                "WHERE id = ?",
                (
                    encrypt_text(name.strip()) if name else None,
                    sharing_needed,
                    budget_paise,
                    visit_time,
                    language,
                    now,
                    enquiry["id"],
                ),
            )
            booking_id = enquiry["id"]
        else:
            booking_id = str(uuid.uuid4())
            connection.execute(
                "INSERT INTO bookings (id, owner_id, hostel_id, student_name, phone, phone_hash, sharing_needed, "
                "budget, status, visit_time, language, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'enquiry', ?, ?, ?, ?)",
                (
                    booking_id,
                    hostel["owner_id"],
                    hostel_id,
                    encrypt_text(name.strip()) if name else None,
                    encrypt_text(normalized_phone),
                    phone_hash,
                    sharing_needed,
                    budget_paise,
                    visit_time,
                    language,
                    now,
                    now,
                ),
            )
        return connection.execute("SELECT * FROM bookings WHERE id = ?", (booking_id,)).fetchone()


async def _send_whatsapp_message(to: str, message: str) -> None:
    if not config.WHATSAPP_ACCESS_TOKEN or not config.WHATSAPP_PHONE_NUMBER_ID:
        raise HTTPException(status_code=503, detail="WhatsApp Cloud API credentials are not configured.")
    url = f"https://graph.facebook.com/{config.WHATSAPP_API_VERSION}/{config.WHATSAPP_PHONE_NUMBER_ID}/messages"
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            url,
            headers={"Authorization": f"Bearer {config.WHATSAPP_ACCESS_TOKEN}"},
            json={
                "messaging_product": "whatsapp",
                "to": to,
                "type": "text",
                "text": {"preview_url": False, "body": message},
            },
        )
        response.raise_for_status()


async def _send_whatsapp_template_message(to: str, message: str) -> None:
    if not config.WHATSAPP_ACCESS_TOKEN or not config.WHATSAPP_PHONE_NUMBER_ID:
        raise HTTPException(status_code=503, detail="WhatsApp Cloud API credentials are not configured.")
    if not config.WHATSAPP_BROADCAST_TEMPLATE:
        raise HTTPException(status_code=503, detail="An approved WhatsApp broadcast template is not configured.")
    url = f"https://graph.facebook.com/{config.WHATSAPP_API_VERSION}/{config.WHATSAPP_PHONE_NUMBER_ID}/messages"
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            url,
            headers={"Authorization": f"Bearer {config.WHATSAPP_ACCESS_TOKEN}"},
            json={
                "messaging_product": "whatsapp",
                "to": to,
                "type": "template",
                "template": {
                    "name": config.WHATSAPP_BROADCAST_TEMPLATE,
                    "language": {"code": config.WHATSAPP_BROADCAST_LANGUAGE},
                    "components": [
                        {
                            "type": "body",
                            "parameters": [{"type": "text", "text": message}],
                        }
                    ],
                },
            },
        )
        response.raise_for_status()


def _payment_reminder_message(recipient: sqlite3.Row) -> str:
    due_date = date.fromisoformat(recipient["payment_due_date"]).strftime("%d %b %Y").lstrip("0")
    amount = Decimal(recipient["amount_due_paise"]) / 100
    return (
        f"Hello {decrypt_text(recipient['name_ciphertext'])}, our records show an outstanding hostel payment of "
        f"₹{amount:,.2f}, due on {due_date}. Please complete payment at your earliest convenience. "
        f"If you have already paid, please disregard this reminder. Thank you, {recipient['hostel_name']}."
    )


@app.get("/api/webhook/whatsapp")
def verify_whatsapp_webhook(
    hub_mode: str | None = Query(default=None, alias="hub.mode"),
    hub_verify_token: str | None = Query(default=None, alias="hub.verify_token"),
    hub_challenge: str | None = Query(default=None, alias="hub.challenge"),
) -> Response:
    if (
        hub_mode == "subscribe"
        and config.WHATSAPP_VERIFY_TOKEN
        and hub_verify_token
        and secrets.compare_digest(hub_verify_token, config.WHATSAPP_VERIFY_TOKEN)
        and hub_challenge
    ):
        return Response(content=hub_challenge, media_type="text/plain")
    raise HTTPException(status_code=403, detail="WhatsApp webhook verification failed.")


@app.post("/api/webhook/whatsapp")
async def whatsapp_webhook(request: Request) -> dict[str, str]:
    if not config.WHATSAPP_APP_SECRET:
        raise HTTPException(status_code=503, detail="WHATSAPP_APP_SECRET is not configured.")
    raw_body = await request.body()
    supplied_signature = request.headers.get("x-hub-signature-256", "")
    expected_signature = "sha256=" + hmac.new(
        config.WHATSAPP_APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    if not secrets.compare_digest(supplied_signature, expected_signature):
        raise HTTPException(status_code=403, detail="Invalid WhatsApp webhook signature.")
    payload = json.loads(raw_body or b"{}")
    try:
        value = payload["entry"][0]["changes"][0]["value"]
        incoming = value["messages"][0]
        phone = incoming["from"]
        message = incoming["text"]["body"].strip()
    except (KeyError, IndexError, TypeError):
        return {"status": "ignored"}
    language = _detect_message_language(message)
    phone_hash = hash_address(_normalize_phone(phone))
    hostel_match = re.search(r"HOSTELID_([A-Za-z0-9-]{8,})", message, re.I)
    hostel_id = hostel_match.group(1) if hostel_match else None
    with database.read_connection() as connection:
        if not hostel_id:
            prior = connection.execute(
                "SELECT hostel_id FROM bookings WHERE phone_hash = ? ORDER BY created_at DESC LIMIT 1",
                (phone_hash,),
            ).fetchone()
            if prior:
                hostel_id = prior["hostel_id"]
        if hostel_id:
            hostel = connection.execute(
                "SELECT id, name FROM hostels WHERE id = ? AND active = 1", (hostel_id,)
            ).fetchone()
        else:
            hostels = connection.execute(
                "SELECT id, name FROM hostels WHERE active = 1 ORDER BY name COLLATE NOCASE LIMIT 2"
            ).fetchall()
            hostel = hostels[0] if len(hostels) == 1 else None
    if not hostel:
        await _send_whatsapp_message(phone, _whatsapp_text(language, "choose_hostel"))
        return {"status": "replied"}

    normalized_message = message.casefold()
    is_vacancy_request = bool(
        re.search(r"vacan|check\s+vacancy|room\s+khali|room\s+chahiye|rooms?\s+available|खाली|कमरा|ఖాళీ|గది", normalized_message, re.I)
    )
    detail_message = re.sub(r"HOSTELID_[A-Za-z0-9-]+", "", message, flags=re.I)
    sharing = _parse_sharing(detail_message)
    budget = _parse_budget(detail_message)
    name = _parse_booking_name(message)
    visit_time = _parse_visit_time(message)
    has_booking_details = name is not None or visit_time is not None
    enquiry = None
    if is_vacancy_request or sharing is not None or budget is not None or has_booking_details:
        enquiry = _upsert_whatsapp_enquiry(
            phone, hostel["id"], language, sharing, budget, name, visit_time
        )

    if enquiry and enquiry["student_name"] and enquiry["visit_time"]:
        try:
            booking = _reserve_booking(
                name=decrypt_text(enquiry["student_name"]),
                phone=phone,
                sharing_needed=enquiry["sharing_needed"],
                budget=Decimal(enquiry["budget"]) / 100 if enquiry["budget"] is not None else None,
                visit_time=enquiry["visit_time"],
                hostel_id=hostel["id"],
                language=language,
                existing_booking_id=enquiry["id"],
            )
            reply = _whatsapp_text(language, "booked", time=enquiry["visit_time"], room=booking["room_no"])
        except HTTPException:
            reply = _whatsapp_text(language, "no_rooms")
    elif sharing is not None or budget is not None:
        with database.read_connection() as connection:
            vacancy = _vacancy_payload(connection, hostel["id"])
        options = [
            room for room in vacancy["vacant_list"]
            if (sharing is None or room["share_count"] == sharing)
            and (budget is None or (room["rent"] is not None and room["rent"] <= float(budget)))
        ][:2]
        if options:
            option_text = "; ".join(
                f"Room {room['room_no']} ({room['sharing_type']}, "
                f"{'Rs ' + str(int(room['rent'])) if room['rent'] is not None else 'rent not set'}, Floor {room['floor']})"
                for room in options
            )
            reply = _whatsapp_text(language, "options", hostel=hostel["name"], rooms=option_text)
        else:
            reply = _whatsapp_text(language, "no_rooms")
    elif is_vacancy_request:
        with database.read_connection() as connection:
            vacancy = _vacancy_payload(connection, hostel["id"])
        if vacancy["vacant_list"]:
            room_text = "; ".join(
                f"Room {room['room_no']} ({room['sharing_type']}, "
                f"{'Rs ' + str(int(room['rent'])) if room['rent'] is not None else 'rent not set'}, Floor {room['floor']})"
                for room in vacancy["vacant_list"]
            )
            reply = _whatsapp_text(
                language,
                "vacancy",
                hostel=hostel["name"],
                count=vacancy["vacant_count"],
                rooms=room_text,
            )
        else:
            reply = _whatsapp_text(language, "no_rooms")
    elif enquiry and (enquiry["sharing_needed"] is None or enquiry["budget"] is None):
        reply = _whatsapp_text(language, "ask_preferences")
    elif enquiry and not enquiry["student_name"]:
        reply = _whatsapp_text(language, "ask_name")
    elif enquiry and not enquiry["visit_time"]:
        reply = _whatsapp_text(language, "ask_time")
    else:
        reply = _whatsapp_text(language, "ask_name_time")
    await _send_whatsapp_message(phone, reply)
    return {"status": "replied"}


@app.delete("/api/rooms/{room_id}")
def delete_room(room_id: str, staff: dict[str, str] = Depends(require_staff_or_platform)) -> dict[str, str]:
    with database.transaction() as connection:
        if staff.get("role") == "developer":
            room = connection.execute(
                "SELECT room.id, room.room_number, hostel.name AS hostel_name, floor.floor_number "
                "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
                "JOIN hostels hostel ON hostel.id = floor.hostel_id "
                "WHERE room.id = ? AND room.active = 1 AND hostel.active = 1",
                (room_id,),
            ).fetchone()
        else:
            room = connection.execute(
                "SELECT room.id, room.room_number, hostel.name AS hostel_name, floor.floor_number "
                "FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
                "JOIN hostels hostel ON hostel.id = floor.hostel_id "
                "WHERE room.id = ? AND room.active = 1 AND hostel.active = 1 AND hostel.owner_id = ?",
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
        reserved = connection.execute(
            "SELECT 1 FROM bookings WHERE room_id_reserved = ? AND status = 'visit_booked' "
            "AND cancelled_at IS NULL AND reservation_expires_at > ? LIMIT 1",
            (room_id, datetime.now(timezone.utc).isoformat()),
        ).fetchone()
        if reserved:
            raise HTTPException(status_code=409, detail="Cancel or expire the room reservation before deleting this room.")
        connection.execute("UPDATE rooms SET active = 0 WHERE id = ?", (room_id,))
        database.write_audit(
            connection,
            None,
            "room.delete",
            "room",
            room_id,
            {
                "room_number": room["room_number"],
                "hostel_name": room["hostel_name"],
                "floor_number": room["floor_number"],
                "history_retained": True,
                "deleted_by": staff["username"],
            },
        )
    return {"status": "deleted", "room_number": room["room_number"]}


@app.get("/api/registration-workspace")
def registration_workspace(staff: dict[str, str] = Depends(require_admin_read)) -> dict[str, object]:
    with database.read_connection() as connection:
        invite_rows = connection.execute(
            "SELECT invite.id, hostel.name AS hostel_name, invite.created_at, invite.expires_at, "
            "invite.used_at, invite.revoked_at FROM registration_invites invite "
            "JOIN hostels hostel ON hostel.id = invite.hostel_id "
            "WHERE hostel.owner_id = ? ORDER BY invite.created_at DESC LIMIT 100",
            (staff["owner_id"],),
        ).fetchall()
        application_rows = connection.execute(
            "SELECT application.*, hostel.name AS hostel_name FROM registration_applications application "
            "JOIN hostels hostel ON hostel.id = application.hostel_id "
            "WHERE application.status = 'pending' AND application.retention_purging_at IS NULL "
            "AND hostel.owner_id = ? "
            "ORDER BY application.submitted_at",
            (staff["owner_id"],),
        ).fetchall()
    applications = []
    for row in application_rows:
        aadhaar = decrypt_text(row["aadhaar_ciphertext"]) if row["aadhaar_ciphertext"] else ""
        documents = []
        if row["person_photo_path"]:
            documents.append(
                {
                    "kind": "person_photo",
                    "url": f"/api/registration-applications/{row['id']}/documents/person_photo",
                    "preview_url": f"/api/registration-applications/{row['id']}/documents/person_photo?inline=true",
                }
            )
        if row["aadhaar_photo_path"]:
            documents.append(
                {
                    "kind": "aadhaar_photo",
                    "url": f"/api/registration-applications/{row['id']}/documents/aadhaar_photo",
                    "preview_url": f"/api/registration-applications/{row['id']}/documents/aadhaar_photo?inline=true",
                }
            )
        applications.append(
            {
                "id": row["id"],
                "name": decrypt_text(row["name_ciphertext"]),
                "mobile": decrypt_text(row["mobile_ciphertext"]),
                "emergency_contact": decrypt_text(row["emergency_contact_ciphertext"])
                if row["emergency_contact_ciphertext"]
                else "",
                "emergency_contact_relationship": decrypt_text(
                    row["emergency_contact_relationship_ciphertext"]
                )
                if row["emergency_contact_relationship_ciphertext"]
                else "",
                "aadhaar_last4": aadhaar[-4:] if aadhaar else "",
                "purpose_of_stay": decrypt_text(row["purpose_of_stay_ciphertext"])
                if row["purpose_of_stay_ciphertext"]
                else "",
                "office_address": decrypt_text(row["office_address_ciphertext"])
                if row["office_address_ciphertext"]
                else "",
                "hostel_id": row["hostel_id"],
                "hostel_name": row["hostel_name"],
                "whatsapp_opt_in": bool(row["whatsapp_opt_in"]),
                "submitted_at": row["submitted_at"],
                "terms_accepted_at": row["terms_accepted_at"],
                "terms_version": row["terms_version"],
                "documents": documents,
            }
        )
    return {
        "invites": [
            {
                "id": row["id"],
                "hostel_name": row["hostel_name"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "used_at": row["used_at"],
                "revoked_at": row["revoked_at"],
            }
            for row in invite_rows
        ],
        "applications": applications,
    }


@app.post("/api/registration-invites", status_code=201)
def create_registration_invite(
    payload: RegistrationInviteRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    token = new_token()
    invite_id = str(uuid.uuid4())
    expires_at = (now + timedelta(days=payload.expires_in_days)).isoformat()
    with database.transaction() as connection:
        hostel = connection.execute(
            "SELECT id, name FROM hostels WHERE id = ? AND owner_id = ? AND active = 1",
            (payload.hostel_id, staff["owner_id"]),
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        connection.execute(
            "INSERT INTO registration_invites "
            "(id, hostel_id, token_hash, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (invite_id, hostel["id"], hash_session_token(token), expires_at, staff["id"], now.isoformat()),
        )
        database.write_audit(
            connection,
            staff["id"],
            "registration.invite.create",
            "registration_invite",
            invite_id,
            {"hostel_id": hostel["id"], "expires_at": expires_at},
        )
    return {"id": invite_id, "path": f"/register/{token}", "expires_at": expires_at}


@app.post("/api/registration-invites/{invite_id}/revoke")
def revoke_registration_invite(
    invite_id: str,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        invite = connection.execute(
            "SELECT invite.id, invite.used_at, invite.revoked_at FROM registration_invites invite "
            "JOIN hostels hostel ON hostel.id = invite.hostel_id "
            "WHERE invite.id = ? AND hostel.owner_id = ?",
            (invite_id, staff["owner_id"]),
        ).fetchone()
        if not invite:
            raise HTTPException(status_code=404, detail="Registration invitation not found.")
        if invite["used_at"]:
            raise HTTPException(status_code=409, detail="This invitation has already been used.")
        if invite["revoked_at"]:
            raise HTTPException(status_code=409, detail="This invitation has already been revoked.")
        connection.execute(
            "UPDATE registration_invites SET revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
            (now, invite_id),
        )
        database.write_audit(
            connection,
            staff["id"],
            "registration.invite.revoke",
            "registration_invite",
            invite_id,
        )
    return {"status": "revoked"}


def active_registration_invite(token: str) -> sqlite3.Row:
    if not re.fullmatch(r"[a-f0-9]{64}", token):
        raise HTTPException(status_code=410, detail="This registration link is invalid or no longer active.")
    now = datetime.now(timezone.utc).isoformat()
    with database.read_connection() as connection:
        invite = connection.execute(
            "SELECT invite.id, invite.hostel_id, hostel.name AS hostel_name FROM registration_invites invite "
            "JOIN hostels hostel ON hostel.id = invite.hostel_id "
            "WHERE invite.token_hash = ? AND invite.used_at IS NULL AND invite.revoked_at IS NULL "
            "AND invite.expires_at > ? AND hostel.active = 1",
            (hash_session_token(token), now),
        ).fetchone()
    if not invite:
        raise HTTPException(status_code=410, detail="This registration link has expired or was already used.")
    return invite


@app.get("/api/join/{token}")
def get_join_registration(token: str) -> dict[str, str]:
    invite = active_registration_invite(token)
    return {"hostel_name": invite["hostel_name"]}


@app.post("/api/join/{token}", status_code=201)
async def submit_join_registration(
    token: str,
    name: str = Form(min_length=1, max_length=80),
    mobile: str = Form(min_length=10, max_length=20),
    emergency_contact: str = Form(default="", max_length=20),
    emergency_contact_relationship: str = Form(default="", max_length=80),
    aadhaar: str = Form(default="", max_length=14),
    purpose_of_stay: str = Form(default="", max_length=120),
    purpose_other: str = Form(default="", max_length=120),
    office_address: str = Form(default="", max_length=300),
    consent: str = Form(),
    terms_accepted: str = Form(default=""),
    terms_version: str = Form(default=""),
    whatsapp_opt_in: bool = Form(default=False),
    person_photo: UploadFile | None = File(default=None),
    aadhaar_photo: UploadFile | None = File(default=None),
) -> dict[str, str]:
    invite = active_registration_invite(token)
    name, mobile = name.strip(), mobile.strip()
    emergency_contact = emergency_contact.strip()
    emergency_contact_relationship = emergency_contact_relationship.strip()
    purpose_of_stay, purpose_other = purpose_of_stay.strip(), purpose_other.strip()
    office_address = office_address.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Enter a valid full name.")
    normalized_mobile = _normalize_phone(mobile)
    normalized_emergency_contact = _normalize_phone(emergency_contact) if emergency_contact else ""
    if bool(normalized_emergency_contact) != bool(emergency_contact_relationship):
        raise HTTPException(
            status_code=422,
            detail="Enter the relationship for the emergency contact number.",
        )
    purpose_of_stay = _validated_purpose_of_stay(purpose_of_stay, purpose_other)
    normalized_aadhaar = re.sub(r"\s", "", aadhaar)
    if normalized_aadhaar and not re.fullmatch(r"[0-9]{12}", normalized_aadhaar):
        raise HTTPException(status_code=422, detail="Aadhaar must contain 12 digits when provided.")
    if consent.lower() not in {"true", "on", "yes", "1"}:
        raise HTTPException(status_code=422, detail="Consent is required to submit this registration.")
    if terms_accepted.lower() not in {"true", "on", "yes", "1"}:
        raise HTTPException(status_code=422, detail="You must accept the hostel rules and regulations.")
    if terms_version != REGISTRATION_TERMS_VERSION:
        raise HTTPException(status_code=409, detail="The hostel rules have changed. Refresh this page and review them.")

    person_image = await read_optional_image(person_photo, "Person photo")
    aadhaar_image = await read_optional_image(aadhaar_photo, "Aadhaar photo")
    if not person_image:
        raise HTTPException(status_code=422, detail="A person photo is required.")
    application_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    stored_documents: dict[str, tuple[str, str]] = {}
    try:
        for kind, image in (("person_photo", person_image), ("aadhaar_photo", aadhaar_image)):
            if image:
                contents, media_type = image
                stored_documents[kind] = (save_encrypted_document(contents), media_type)
        with database.transaction() as connection:
            updated = connection.execute(
                "UPDATE registration_invites SET used_at = ? WHERE id = ? AND token_hash = ? "
                "AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ? "
                "AND EXISTS (SELECT 1 FROM hostels WHERE hostels.id = registration_invites.hostel_id "
                "AND hostels.active = 1)",
                (now, invite["id"], hash_session_token(token), now),
            )
            if updated.rowcount != 1:
                raise HTTPException(status_code=410, detail="This registration link has expired or was already used.")
            connection.execute(
                "INSERT INTO registration_applications "
                "(id, invite_id, hostel_id, name_ciphertext, mobile_ciphertext, emergency_contact_ciphertext, "
                "emergency_contact_relationship_ciphertext, "
                "aadhaar_ciphertext, purpose_of_stay_ciphertext, office_address_ciphertext, whatsapp_opt_in, "
                "terms_accepted_at, terms_version, "
                "person_photo_path, person_photo_media_type, aadhaar_photo_path, aadhaar_photo_media_type, submitted_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    application_id,
                    invite["id"],
                    invite["hostel_id"],
                    encrypt_text(name),
                    encrypt_text(normalized_mobile),
                    encrypt_text(normalized_emergency_contact) if normalized_emergency_contact else None,
                    encrypt_text(emergency_contact_relationship) if emergency_contact_relationship else None,
                    encrypt_text(normalized_aadhaar) if normalized_aadhaar else None,
                    encrypt_text(purpose_of_stay) if purpose_of_stay else None,
                    encrypt_text(office_address) if office_address else None,
                    int(whatsapp_opt_in),
                    now,
                    REGISTRATION_TERMS_VERSION,
                    stored_documents.get("person_photo", (None, None))[0],
                    stored_documents.get("person_photo", (None, None))[1],
                    stored_documents.get("aadhaar_photo", (None, None))[0],
                    stored_documents.get("aadhaar_photo", (None, None))[1],
                    now,
                ),
            )
            database.write_audit(
                connection,
                None,
                "registration.application.submit",
                "registration_application",
                application_id,
                {
                    "hostel_id": invite["hostel_id"],
                    "terms_version": REGISTRATION_TERMS_VERSION,
                    "terms_accepted_at": now,
                },
            )
    except Exception:
        for encrypted_path, _ in stored_documents.values():
            remove_local_encrypted_document(encrypted_path)
        raise
    return {"status": "submitted"}


@app.get("/api/registration-applications/{application_id}/documents/{kind}")
def download_registration_document(
    application_id: str,
    kind: str,
    inline: bool = Query(default=False),
    staff: dict[str, str] = Depends(require_admin_read),
) -> Response:
    path_column = {
        "person_photo": "person_photo_path",
        "aadhaar_photo": "aadhaar_photo_path",
    }.get(kind)
    media_type_column = {
        "person_photo": "person_photo_media_type",
        "aadhaar_photo": "aadhaar_photo_media_type",
    }.get(kind)
    if not path_column or not media_type_column:
        raise HTTPException(status_code=404, detail="Registration document not found.")
    with database.transaction() as connection:
        row = connection.execute(
            f"SELECT application.{path_column} AS encrypted_path, "
            f"application.{media_type_column} AS media_type FROM registration_applications application "
            "JOIN hostels hostel ON hostel.id = application.hostel_id "
            "WHERE application.id = ? AND hostel.owner_id = ? AND application.status = 'pending' "
            "AND application.retention_purging_at IS NULL",
            (application_id, staff["owner_id"]),
        ).fetchone()
        if not row or not row["encrypted_path"]:
            raise HTTPException(status_code=404, detail="Registration document not found.")
        if inline and row["media_type"] not in IMAGE_SIGNATURES:
            raise HTTPException(status_code=415, detail="Only image documents can be previewed.")
        database.write_audit(
            connection,
            staff["id"],
            "registration.document.preview" if inline else "registration.document.download",
            "registration_application",
            application_id,
            {"kind": kind},
        )
    return Response(
        content=read_document(row["encrypted_path"]),
        media_type=row["media_type"],
        headers={
            "Content-Disposition": f"{'inline' if inline else 'attachment'}; filename=registration-document",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.post("/api/registration-applications/{application_id}/approve")
def approve_registration_application(
    application_id: str,
    payload: RegistrationApprovalRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, str]:
    name = None
    joined = parse_date(payload.joining_date, "joining date")
    payment_due = due_date_after_one_month(joined)
    if payload.payment_status == "unpaid":
        amount_due_paise = amount_to_paise(str(payload.amount_due))
    else:
        if payload.amount_due:
            raise HTTPException(status_code=422, detail="A paid resident cannot have an outstanding balance.")
        amount_due_paise = 0
    resident_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        application = connection.execute(
            "SELECT application.*, hostel.owner_id FROM registration_applications application "
            "JOIN hostels hostel ON hostel.id = application.hostel_id "
            "WHERE application.id = ? AND application.status = 'pending' "
            "AND application.retention_purging_at IS NULL AND hostel.owner_id = ?",
            (application_id, staff["owner_id"]),
        ).fetchone()
        if not application:
            raise HTTPException(status_code=404, detail="Pending registration application not found.")
        claimed = connection.execute(
            "UPDATE registration_applications SET status = 'approved', reviewed_at = ?, reviewed_by = ? "
            "WHERE id = ? AND status = 'pending' AND retention_purging_at IS NULL",
            (now, staff["id"], application_id),
        )
        if claimed.rowcount != 1:
            raise HTTPException(status_code=409, detail="This application has already been reviewed.")
        room = connection.execute(
            "SELECT room.room_number, room.share_count, room.floor_id, floor.floor_number, hostel.id AS hostel_id, "
            "hostel.name AS hostel_name FROM rooms room JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE room.id = ? AND room.active = 1 AND hostel.active = 1 AND hostel.owner_id = ? "
            "AND hostel.id = ?",
            (payload.room_id, staff["owner_id"], application["hostel_id"]),
        ).fetchone()
        if not room:
            raise HTTPException(status_code=422, detail="Choose a valid room in the applicant's hostel.")
        if payload.bed_number > room["share_count"]:
            raise HTTPException(status_code=422, detail="That bed number exceeds this room's sharing capacity.")
        reserved = connection.execute(
            "SELECT 1 FROM bookings WHERE room_id_reserved = ? AND status = 'visit_booked' "
            "AND cancelled_at IS NULL AND reservation_expires_at > ? LIMIT 1",
            (payload.room_id, now),
        ).fetchone()
        if reserved:
            raise HTTPException(status_code=409, detail="This room is reserved for a visit. Choose another room.")
        occupied = connection.execute(
            "SELECT 1 FROM residents WHERE room_id = ? AND bed_number = ? AND checked_out_at IS NULL",
            (payload.room_id, payload.bed_number),
        ).fetchone()
        if occupied:
            raise HTTPException(status_code=409, detail="That bed is already occupied. Choose another bed.")
        name = decrypt_text(application["name_ciphertext"])
        connection.execute(
            "INSERT INTO residents (id, name_ciphertext, mobile_ciphertext, emergency_contact_ciphertext, "
            "emergency_contact_relationship_ciphertext, "
            "aadhaar_ciphertext, purpose_of_stay_ciphertext, office_address_ciphertext, room_id, bed_number, "
            "joining_date, payment_due_date, payment_status, amount_due_paise, whatsapp_opt_in, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                resident_id,
                application["name_ciphertext"],
                application["mobile_ciphertext"],
                application["emergency_contact_ciphertext"],
                application["emergency_contact_relationship_ciphertext"],
                application["aadhaar_ciphertext"],
                application["purpose_of_stay_ciphertext"],
                application["office_address_ciphertext"],
                payload.room_id,
                payload.bed_number,
                joined.isoformat(),
                payment_due.isoformat(),
                payload.payment_status,
                amount_due_paise,
                application["whatsapp_opt_in"],
                staff["id"],
                now,
            ),
        )
        for kind, path_column, media_type_column in (
            ("person_photo", "person_photo_path", "person_photo_media_type"),
            ("aadhaar_photo", "aadhaar_photo_path", "aadhaar_photo_media_type"),
        ):
            encrypted_path = application[path_column]
            if encrypted_path:
                document_id = str(uuid.uuid4())
                connection.execute(
                    "INSERT INTO documents (id, resident_id, kind, encrypted_path, media_type, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (document_id, resident_id, kind, encrypted_path, application[media_type_column], now),
                )
                database.write_audit(
                    connection,
                    staff["id"],
                    "document.upload",
                    "document",
                    document_id,
                    {"resident_id": resident_id, "kind": kind},
                )
        connection.execute(
            "UPDATE registration_applications SET resident_id = ? WHERE id = ? AND status = 'approved' "
            "AND reviewed_by = ?",
            (resident_id, application_id, staff["id"]),
        )
        connection.execute(
            "UPDATE registration_invites SET used_at = COALESCE(used_at, ?) WHERE id = ?",
            (now, application["invite_id"]),
        )
        database.write_audit(
            connection,
            staff["id"],
            "registration.application.approve",
            "registration_application",
            application_id,
            {"resident_id": resident_id, "room_id": payload.room_id, "bed_number": payload.bed_number},
        )
        database.write_audit(
            connection,
            staff["id"],
            "resident.checkin",
            "resident",
            resident_id,
            {
                "room": room["room_number"],
                "room_id": payload.room_id,
                "room_number": room["room_number"],
                "hostel_name": room["hostel_name"],
                "floor_number": room["floor_number"],
                "bed_number": payload.bed_number,
                "payment_status": payload.payment_status,
                "amount_due_paise": amount_due_paise,
                "payment_due_date": payment_due.isoformat(),
                "registration_application_id": application_id,
            },
        )
    return {"status": "approved", "resident_id": resident_id, "name": name or ""}


@app.post("/api/residents", status_code=201)
async def create_resident(
    name: str = Form(min_length=1, max_length=80),
    mobile: str = Form(min_length=10, max_length=20),
    emergency_contact: str = Form(min_length=10, max_length=20),
    emergency_contact_relationship: str = Form(min_length=1, max_length=80),
    aadhaar: str = Form(min_length=12, max_length=14),
    purpose_of_stay: str = Form(min_length=1, max_length=120),
    purpose_other: str = Form(default="", max_length=120),
    office_address: str = Form(min_length=1, max_length=300),
    room: str = Form(min_length=1, max_length=64),
    bed_number: int = Form(ge=1, le=20),
    joining_date: str = Form(),
    payment_status: Literal["paid", "unpaid"] = Form(),
    amount_due: str = Form(default=""),
    whatsapp_opt_in: bool = Form(default=False),
    person_photo: UploadFile = File(...),
    aadhaar_photo: UploadFile = File(...),
    staff: dict[str, str] = Depends(require_write),
) -> dict[str, str]:
    name, mobile = name.strip(), mobile.strip()
    emergency_contact = emergency_contact.strip()
    emergency_contact_relationship = emergency_contact_relationship.strip()
    purpose_of_stay, purpose_other = purpose_of_stay.strip(), purpose_other.strip()
    office_address = office_address.strip()
    if not name or len(name) > 80:
        raise HTTPException(status_code=422, detail="Enter a valid full name.")
    normalized_mobile = _normalize_phone(mobile)
    normalized_emergency_contact = _normalize_phone(emergency_contact) if emergency_contact else ""
    if not normalized_emergency_contact or not emergency_contact_relationship:
        raise HTTPException(
            status_code=422,
            detail="Enter an emergency contact number and relationship.",
        )
    purpose_of_stay = _validated_purpose_of_stay(purpose_of_stay, purpose_other)
    if not purpose_of_stay:
        raise HTTPException(status_code=422, detail="Choose a purpose of stay.")
    normalized_aadhaar = re.sub(r"\s", "", aadhaar)
    if not re.fullmatch(r"[0-9]{12}", normalized_aadhaar):
        raise HTTPException(status_code=422, detail="Aadhaar must contain 12 digits.")
    if not office_address:
        raise HTTPException(status_code=422, detail="Enter the workplace or college address.")
    joined = parse_date(joining_date, "joining date")
    payment_due = due_date_after_one_month(joined)
    amount_due_paise = amount_to_paise(amount_due) if payment_status == "unpaid" else 0
    if payment_status == "paid" and amount_due.strip():
        raise HTTPException(status_code=422, detail="A paid resident cannot have an outstanding balance.")

    person_image = await read_required_image(person_photo, "Person photo")
    aadhaar_image = await read_required_image(aadhaar_photo, "Aadhaar photo")
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
            reserved = connection.execute(
                "SELECT 1 FROM bookings WHERE room_id_reserved = ? AND status = 'visit_booked' "
                "AND cancelled_at IS NULL AND reservation_expires_at > ? LIMIT 1",
                (room, datetime.now(timezone.utc).isoformat()),
            ).fetchone()
            if reserved:
                raise HTTPException(status_code=409, detail="This room is reserved for a visit. Choose another room.")
            if bed_number > room_record["share_count"]:
                raise HTTPException(status_code=422, detail="That bed number exceeds this room's sharing capacity.")
            connection.execute(
                "INSERT INTO residents (id, name_ciphertext, mobile_ciphertext, emergency_contact_ciphertext, "
                "emergency_contact_relationship_ciphertext, "
                "aadhaar_ciphertext, purpose_of_stay_ciphertext, office_address_ciphertext, room_id, bed_number, "
                "joining_date, payment_due_date, payment_status, amount_due_paise, whatsapp_opt_in, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    resident_id,
                    encrypt_text(name),
                    encrypt_text(normalized_mobile),
                    encrypt_text(normalized_emergency_contact) if normalized_emergency_contact else None,
                    encrypt_text(emergency_contact_relationship) if emergency_contact_relationship else None,
                    encrypt_text(normalized_aadhaar) if normalized_aadhaar else None,
                    encrypt_text(purpose_of_stay) if purpose_of_stay else None,
                    encrypt_text(office_address) if office_address else None,
                    room,
                    bed_number,
                    joined.isoformat(),
                    payment_due.isoformat(),
                    payment_status,
                    amount_due_paise,
                    int(whatsapp_opt_in),
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


@app.patch("/api/residents/{resident_id}/whatsapp-consent")
def update_resident_whatsapp_consent(
    resident_id: str,
    payload: WhatsAppConsentRequest,
    staff: dict[str, str] = Depends(require_write),
) -> dict[str, bool]:
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT resident.whatsapp_opt_in FROM residents resident "
            "JOIN rooms room ON room.id = resident.room_id JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE resident.id = ? AND resident.checked_out_at IS NULL AND hostel.owner_id = ?",
            (resident_id, staff["owner_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Active resident not found.")
        connection.execute(
            "UPDATE residents SET whatsapp_opt_in = ? WHERE id = ? AND checked_out_at IS NULL",
            (int(payload.enabled), resident_id),
        )
        database.write_audit(
            connection,
            staff["id"],
            "resident.whatsapp_consent",
            "resident",
            resident_id,
            {"enabled": payload.enabled, "previous_enabled": bool(row["whatsapp_opt_in"])},
        )
    return {"whatsapp_opt_in": payload.enabled}


@app.get("/api/whatsapp/broadcast-status")
def whatsapp_broadcast_status(staff: dict[str, str] = Depends(require_admin_read)) -> dict[str, object]:
    missing = []
    if not config.WHATSAPP_ACCESS_TOKEN or not config.WHATSAPP_PHONE_NUMBER_ID:
        missing.append("WhatsApp Cloud API credentials")
    if not config.WHATSAPP_BROADCAST_TEMPLATE:
        missing.append("an approved WhatsApp broadcast template")
    return {
        "ready": not missing,
        "reason": (
            "WhatsApp broadcasts are ready."
            if not missing
            else f"Sending is disabled until you configure {' and '.join(missing)}."
        ),
    }


@app.post("/api/whatsapp/broadcast")
async def send_whatsapp_broadcast(
    payload: WhatsAppBroadcastRequest,
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, object]:
    if not config.WHATSAPP_ACCESS_TOKEN or not config.WHATSAPP_PHONE_NUMBER_ID:
        raise HTTPException(status_code=503, detail="WhatsApp Cloud API credentials are not configured.")
    if not config.WHATSAPP_BROADCAST_TEMPLATE:
        raise HTTPException(
            status_code=503,
            detail="An approved WhatsApp broadcast template must be configured before sending.",
        )
    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Enter an announcement message.")
    with database.read_connection() as connection:
        hostel = connection.execute(
            "SELECT id FROM hostels WHERE id = ? AND owner_id = ? AND active = 1",
            (payload.hostel_id, staff["owner_id"]),
        ).fetchone()
        if not hostel:
            raise HTTPException(status_code=404, detail="Active hostel not found.")
        recipients = connection.execute(
            "SELECT resident.id, resident.name_ciphertext, resident.mobile_ciphertext FROM residents resident "
            "JOIN rooms room ON room.id = resident.room_id JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE hostel.id = ? AND hostel.owner_id = ? AND hostel.active = 1 "
            "AND resident.checked_out_at IS NULL AND resident.whatsapp_opt_in = 1 "
            "ORDER BY resident.created_at",
            (payload.hostel_id, staff["owner_id"]),
        ).fetchall()
    if not recipients:
        raise HTTPException(status_code=409, detail="No active guests in this hostel have opted in to WhatsApp updates.")

    semaphore = asyncio.Semaphore(5)

    async def send_one(recipient: sqlite3.Row) -> tuple[bool, dict[str, str] | None]:
        try:
            async with semaphore:
                await _send_whatsapp_template_message(
                    _whatsapp_recipient_number(decrypt_text(recipient["mobile_ciphertext"])),
                    message,
                )
        except (httpx.HTTPError, HTTPException) as error:
            logger.warning(
                "WhatsApp broadcast delivery failed for resident %s (%s).",
                recipient["id"],
                type(error).__name__,
            )
            return False, {"id": recipient["id"], "name": decrypt_text(recipient["name_ciphertext"])}
        return True, None

    delivery_results = await asyncio.gather(*(send_one(recipient) for recipient in recipients))
    failed_residents = [failure for sent, failure in delivery_results if not sent and failure]
    sent_count = len(delivery_results) - len(failed_residents)
    with database.transaction() as connection:
        database.write_audit(
            connection,
            staff["id"],
            "whatsapp.broadcast",
            "hostel",
            payload.hostel_id,
            {
                "recipient_count": len(recipients),
                "sent_count": sent_count,
                "failed_count": len(failed_residents),
                "message_sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            },
        )
    return {
        "recipient_count": len(recipients),
        "sent_count": sent_count,
        "failed_count": len(failed_residents),
        "failed_residents": failed_residents,
    }


@app.post("/api/whatsapp/payment-reminders")
async def send_whatsapp_payment_reminders(
    staff: dict[str, str] = Depends(require_admin),
) -> dict[str, object]:
    if not config.WHATSAPP_ACCESS_TOKEN or not config.WHATSAPP_PHONE_NUMBER_ID:
        raise HTTPException(status_code=503, detail="WhatsApp Cloud API credentials are not configured.")
    if not config.WHATSAPP_BROADCAST_TEMPLATE:
        raise HTTPException(
            status_code=503,
            detail="An approved WhatsApp broadcast template must be configured before sending.",
        )

    today = datetime.now(ZoneInfo("Asia/Kolkata")).date()
    cooldown_cutoff = (today - timedelta(days=1)).isoformat()
    sent_date = today.isoformat()
    now = datetime.now(timezone.utc).isoformat()
    with database.transaction() as connection:
        eligible = connection.execute(
            "SELECT resident.id, resident.name_ciphertext, resident.mobile_ciphertext, "
            "resident.payment_due_date, resident.amount_due_paise, hostel.name AS hostel_name "
            "FROM residents resident JOIN rooms room ON room.id = resident.room_id "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE hostel.owner_id = ? AND hostel.active = 1 AND resident.checked_out_at IS NULL "
            "AND resident.payment_status = 'unpaid' AND resident.amount_due_paise > 0 "
            "AND resident.whatsapp_opt_in = 1 ORDER BY resident.created_at",
            (staff["owner_id"],),
        ).fetchall()
        candidates = connection.execute(
            "SELECT resident.id, resident.name_ciphertext, resident.mobile_ciphertext, "
            "resident.payment_due_date, resident.amount_due_paise, hostel.name AS hostel_name "
            "FROM residents resident JOIN rooms room ON room.id = resident.room_id "
            "JOIN floors floor ON floor.id = room.floor_id JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE hostel.owner_id = ? AND hostel.active = 1 AND resident.checked_out_at IS NULL "
            "AND resident.payment_status = 'unpaid' AND resident.amount_due_paise > 0 "
            "AND resident.whatsapp_opt_in = 1 "
            "AND NOT EXISTS (SELECT 1 FROM whatsapp_payment_reminders reminder "
            "WHERE reminder.resident_id = resident.id AND reminder.sent_date >= ?) "
            "ORDER BY resident.created_at",
            (staff["owner_id"], cooldown_cutoff),
        ).fetchall()
        recipients = []
        for candidate in candidates:
            reservation = connection.execute(
                "INSERT OR IGNORE INTO whatsapp_payment_reminders (resident_id, sent_date, created_at) "
                "VALUES (?, ?, ?)",
                (candidate["id"], sent_date, now),
            )
            if reservation.rowcount:
                recipients.append(candidate)

    semaphore = asyncio.Semaphore(5)

    async def send_one(recipient: sqlite3.Row) -> tuple[bool, dict[str, str] | None]:
        try:
            async with semaphore:
                await _send_whatsapp_template_message(
                    _whatsapp_recipient_number(decrypt_text(recipient["mobile_ciphertext"])),
                    _payment_reminder_message(recipient),
                )
        except (httpx.HTTPError, HTTPException) as error:
            logger.warning(
                "WhatsApp payment reminder delivery failed for resident %s (%s).",
                recipient["id"],
                type(error).__name__,
            )
            with database.transaction() as connection:
                connection.execute(
                    "DELETE FROM whatsapp_payment_reminders WHERE resident_id = ? AND sent_date = ?",
                    (recipient["id"], sent_date),
                )
            return False, {"id": recipient["id"], "name": decrypt_text(recipient["name_ciphertext"])}
        return True, None

    delivery_results = await asyncio.gather(*(send_one(recipient) for recipient in recipients))
    failed_residents = [failure for sent, failure in delivery_results if not sent and failure]
    sent_count = len(delivery_results) - len(failed_residents)
    skipped_count = len(eligible) - len(recipients)
    with database.transaction() as connection:
        database.write_audit(
            connection,
            staff["id"],
            "whatsapp.payment_reminders",
            "staff",
            staff["owner_id"],
            {
                "eligible_count": len(eligible),
                "sent_count": sent_count,
                "skipped_count": skipped_count,
                "failed_count": len(failed_residents),
            },
        )
    return {
        "eligible_count": len(eligible),
        "sent_count": sent_count,
        "skipped_count": skipped_count,
        "failed_count": len(failed_residents),
        "failed_residents": failed_residents,
    }


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
def download_document(
    document_id: str,
    inline: bool = Query(default=False),
    staff: dict[str, str] = Depends(current_staff),
) -> Response:
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT document.encrypted_path, document.media_type, document.resident_id FROM documents document "
            "JOIN residents resident ON resident.id = document.resident_id "
            "JOIN rooms room ON room.id = resident.room_id JOIN floors floor ON floor.id = room.floor_id "
            "JOIN hostels hostel ON hostel.id = floor.hostel_id "
            "WHERE document.id = ? AND hostel.owner_id = ? AND resident.retention_purging_at IS NULL",
            (document_id, staff["owner_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Document not found.")
        if inline and row["media_type"] not in IMAGE_SIGNATURES:
            raise HTTPException(status_code=415, detail="Only image documents can be previewed.")
        database.write_audit(
            connection,
            staff["id"],
            "document.preview" if inline else "document.download",
            "document",
            document_id,
            {"resident_id": row["resident_id"]},
        )
    return Response(
        content=read_document(row["encrypted_path"]),
        media_type=row["media_type"],
        headers={
            "Content-Disposition": f"{'inline' if inline else 'attachment'}; filename=resident-document",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
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
    if payload.role != "warden":
        raise HTTPException(status_code=403, detail="Only the employer portal can register hostel owners.")
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