import hashlib
import hmac
import os

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken

from app.config import encryption_key

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


def encrypt_bytes(value: bytes) -> bytes:
    return Fernet(encryption_key()).encrypt(value)


def decrypt_bytes(value: bytes) -> bytes:
    try:
        return Fernet(encryption_key()).decrypt(value)
    except InvalidToken as error:
        raise ValueError("Encrypted data could not be authenticated") from error


def encrypt_text(value: str) -> str:
    return encrypt_bytes(value.encode("utf-8")).decode("ascii")


def decrypt_text(value: str) -> str:
    return decrypt_bytes(value.encode("ascii")).decode("utf-8")


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def hash_address(address: str) -> str:
    key = encryption_key()
    return hmac.new(key, address.encode("utf-8"), hashlib.sha256).hexdigest()


def new_token() -> str:
    return os.urandom(32).hex()