import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
for environment_file in (".env.production.local", ".env.local", ".env"):
    load_dotenv(ROOT_DIR / environment_file, override=False)

VERCEL_DEPLOYMENT = os.environ.get("VERCEL", "").lower() == "1"
DEFAULT_DATA_DIR = Path("/tmp/hostel-data") if VERCEL_DEPLOYMENT else ROOT_DIR / "data"
DATA_DIR = Path(os.environ.get("HOSTEL_DATA_DIR", DEFAULT_DATA_DIR)).resolve()
DATABASE_PATH = DATA_DIR / "hostel.sqlite3"
DOCUMENTS_DIR = DATA_DIR / "documents"
BACKUPS_DIR = DATA_DIR / "backups"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
BLOB_READ_WRITE_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN", "").strip()
COOKIE_NAME = "hostel_session"
PLATFORM_COOKIE_NAME = "hostel_platform_session"
COOKIE_SECURE = os.environ.get("HOSTEL_COOKIE_SECURE", "true" if VERCEL_DEPLOYMENT else "false").lower() == "true"
SESSION_HOURS = 12
MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_BACKUPS = 14
WHATSAPP_VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_ACCESS_TOKEN = os.environ.get("WHATSAPP_ACCESS_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_APP_SECRET = os.environ.get("WHATSAPP_APP_SECRET", "").strip()
WHATSAPP_BUSINESS_NUMBER = os.environ.get("WHATSAPP_BUSINESS_NUMBER", "").strip().lstrip("+")
WHATSAPP_API_VERSION = os.environ.get("WHATSAPP_API_VERSION", "v22.0").strip()


def encryption_key() -> bytes:
    key = os.environ.get("HOSTEL_ENCRYPTION_KEY", "").encode("ascii")
    if not key:
        raise RuntimeError("HOSTEL_ENCRYPTION_KEY is missing. Run `python -m app.setup` first.")
    return key