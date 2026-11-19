import os
from pathlib import Path

from dotenv import load_dotenv

from app.setup import ensure_environment_file

ROOT_DIR = Path(__file__).resolve().parent.parent
VERCEL_DEPLOYMENT = os.environ.get("VERCEL", "").lower() == "1"
environment_files = (
    (".env.production.local", ".env.local", ".env")
    if VERCEL_DEPLOYMENT
    else (".env.local", ".env")
)
for environment_file in environment_files:
    load_dotenv(ROOT_DIR / environment_file, override=True)

DEFAULT_DATA_DIR = Path("/tmp/hostel-data") if VERCEL_DEPLOYMENT else ROOT_DIR / "data"
DATA_DIR = Path(os.environ.get("HOSTEL_DATA_DIR", DEFAULT_DATA_DIR)).resolve()
DATABASE_PATH = DATA_DIR / "hostel.sqlite3"
DOCUMENTS_DIR = DATA_DIR / "documents"
BACKUPS_DIR = DATA_DIR / "backups"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
BLOB_READ_WRITE_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
CRON_SECRET = os.environ.get("CRON_SECRET", "").strip()
COOKIE_NAME = "hostel_session"
PLATFORM_COOKIE_NAME = "hostel_platform_session"
COOKIE_SECURE = os.environ.get("HOSTEL_COOKIE_SECURE", "true" if VERCEL_DEPLOYMENT else "false").lower() == "true"
SESSION_HOURS = 12
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_BACKUPS = 14
WHATSAPP_VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_ACCESS_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_BROADCAST_TEMPLATE = os.environ.get("WHATSAPP_BROADCAST_TEMPLATE", "").strip()
WHATSAPP_BROADCAST_LANGUAGE = os.environ.get("WHATSAPP_BROADCAST_LANGUAGE", "en").strip()
WHATSAPP_APP_SECRET = os.environ.get("WHATSAPP_APP_SECRET", "").strip()
WHATSAPP_BUSINESS_NUMBER = os.environ.get("WHATSAPP_BUSINESS_NUMBER", "").strip().lstrip("+")
WHATSAPP_API_VERSION = os.environ.get("WHATSAPP_API_VERSION", "v22.0").strip()
HOSTEL_SMTP_HOST = os.environ.get("HOSTEL_SMTP_HOST", os.environ.get("SMTP_HOST", "")).strip()
HOSTEL_SMTP_PORT = int(
    os.environ.get("HOSTEL_SMTP_PORT", os.environ.get("SMTP_PORT", "587"))
)
HOSTEL_SMTP_USERNAME = os.environ.get(
    "HOSTEL_SMTP_USERNAME",
    os.environ.get("SMTP_USERNAME", ""),
).strip()
HOSTEL_SMTP_PASSWORD = os.environ.get(
    "HOSTEL_SMTP_PASSWORD",
    os.environ.get("SMTP_PASSWORD", ""),
)
HOSTEL_SMTP_FROM = os.environ.get(
    "HOSTEL_SMTP_FROM",
    os.environ.get("SMTP_FROM", ""),
).strip()
HOSTEL_SMTP_USE_SSL = os.environ.get(
    "HOSTEL_SMTP_USE_SSL",
    os.environ.get("SMTP_USE_SSL", "false"),
).lower() == "true"


def encryption_key() -> bytes:
    key = os.environ.get("HOSTEL_ENCRYPTION_KEY", "").strip()
    if not key:
        ensure_environment_file()
        key = os.environ.get("HOSTEL_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("HOSTEL_ENCRYPTION_KEY is missing. Run `python -m app.setup` first.")
    try:
        from cryptography.fernet import Fernet

        Fernet(key)
    except ValueError as error:
        raise RuntimeError(
            "HOSTEL_ENCRYPTION_KEY must be a valid 32-byte Fernet key. Run `python -m app.setup` to generate one."
        ) from error
    return key.encode("ascii")