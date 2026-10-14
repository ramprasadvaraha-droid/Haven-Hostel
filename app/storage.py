import uuid
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from app import config
from app.security import decrypt_bytes, encrypt_bytes


BLOB_API = "https://blob.vercel-storage.com"
BLOB_HOST_SUFFIX = ".blob.vercel-storage.com"


def validate_blob_url(blob_url: str) -> str:
    parsed = urlparse(blob_url)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(BLOB_HOST_SUFFIX):
        raise ValueError("Stored file URL is not a Vercel Blob URL.")
    return blob_url


def put_encrypted_blob(pathname: str, encrypted_contents: bytes) -> str:
    if not config.BLOB_READ_WRITE_TOKEN:
        raise RuntimeError("BLOB_READ_WRITE_TOKEN is required for Vercel Blob storage.")
    url = f"{BLOB_API}/{quote(pathname, safe='/')}"
    response = httpx.put(
        url,
        content=encrypted_contents,
        headers={
            "Authorization": f"Bearer {config.BLOB_READ_WRITE_TOKEN}",
            "x-api-version": "7",
            "x-content-type": "application/octet-stream",
        },
        timeout=30,
    )
    response.raise_for_status()
    result = response.json()
    blob_url = result.get("url")
    if not isinstance(blob_url, str):
        raise RuntimeError("Vercel Blob did not return a valid object URL.")
    return validate_blob_url(blob_url)


def save_encrypted_document(contents: bytes) -> str:
    encrypted_contents = encrypt_bytes(contents)
    if config.BLOB_READ_WRITE_TOKEN:
        return put_encrypted_blob(f"resident-documents/{uuid.uuid4().hex}.enc", encrypted_contents)

    config.DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.enc"
    destination = config.DOCUMENTS_DIR / filename
    with destination.open("xb") as document_file:
        document_file.write(encrypted_contents)
    try:
        destination.chmod(0o600)
    except OSError:
        pass
    return filename


def read_encrypted_object(location: str) -> bytes:
    if location.startswith("https://"):
        if not config.BLOB_READ_WRITE_TOKEN:
            raise RuntimeError("BLOB_READ_WRITE_TOKEN is required for Vercel Blob storage.")
        response = httpx.get(
            validate_blob_url(location),
            headers={
                "Authorization": f"Bearer {config.BLOB_READ_WRITE_TOKEN}",
                "x-api-version": "7",
            },
            timeout=30,
        )
        response.raise_for_status()
        return response.content

    filename = Path(location)
    if filename.name != location or filename.suffix != ".enc":
        raise FileNotFoundError("Encrypted document not found.")
    document_path = config.DOCUMENTS_DIR / filename
    if document_path.parent != config.DOCUMENTS_DIR or not document_path.is_file():
        raise FileNotFoundError("Encrypted document not found.")
    return document_path.read_bytes()


def read_document(location: str) -> bytes:
    return decrypt_bytes(read_encrypted_object(location))


def remove_local_encrypted_document(location: str) -> None:
    if location.startswith("https://"):
        return
    filename = Path(location)
    if filename.name == location and filename.suffix == ".enc":
        (config.DOCUMENTS_DIR / filename).unlink(missing_ok=True)