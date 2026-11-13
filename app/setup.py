import os
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT_DIR / ".env"


def ensure_environment_file() -> None:
    if ENV_FILE.exists():
        return
    content = (
        f"HOSTEL_ENCRYPTION_KEY={Fernet.generate_key().decode('ascii')}\n"
        "HOSTEL_COOKIE_SECURE=false\n"
    )
    descriptor = os.open(ENV_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as environment_file:
        environment_file.write(content)
    load_dotenv(ENV_FILE, override=True)


def main() -> None:
    if ENV_FILE.exists():
        print(".env already exists; left it unchanged.")
        return
    ensure_environment_file()
    print("Created .env with fresh local encryption keys. Keep it private and backed up securely.")


if __name__ == "__main__":
    main()