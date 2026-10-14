import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


ROOT_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT_DIR / ".env"


def main() -> None:
    content = (
        f"HOSTEL_ENCRYPTION_KEY={Fernet.generate_key().decode('ascii')}\n"
        "HOSTEL_COOKIE_SECURE=false\n"
    )
    try:
        descriptor = os.open(ENV_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        print(".env already exists; left it unchanged.")
        return
    with os.fdopen(descriptor, "w", encoding="utf-8") as environment_file:
        environment_file.write(content)
    print("Created .env with fresh local encryption keys. Keep it private and backed up securely.")


if __name__ == "__main__":
    main()