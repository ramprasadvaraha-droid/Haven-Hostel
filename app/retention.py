import logging
from calendar import monthrange
from datetime import datetime, timedelta, timezone

import httpx

from app import database
from app.storage import remove_encrypted_document


logger = logging.getLogger(__name__)
RETENTION_BATCH_SIZE = 10
PURGE_CLAIM_TIMEOUT = timedelta(minutes=15)


def _three_months_before(value: datetime) -> datetime:
    month = value.month - 3
    year = value.year
    if month < 1:
        month += 12
        year -= 1
    return value.replace(year=year, month=month, day=min(value.day, monthrange(year, month)[1]))


def _unique_paths(*paths: str | None) -> list[str]:
    return list(dict.fromkeys(path for path in paths if path))


def _application_paths(connection, application_id: str) -> list[str]:
    row = connection.execute(
        "SELECT person_photo_path, aadhaar_photo_path FROM registration_applications WHERE id = ?",
        (application_id,),
    ).fetchone()
    return _unique_paths(row["person_photo_path"], row["aadhaar_photo_path"]) if row else []


def _resident_paths(connection, resident_id: str) -> list[str]:
    paths = [
        row["encrypted_path"]
        for row in connection.execute(
            "SELECT encrypted_path FROM documents WHERE resident_id = ?",
            (resident_id,),
        ).fetchall()
    ]
    applications = connection.execute(
        "SELECT person_photo_path, aadhaar_photo_path FROM registration_applications WHERE resident_id = ?",
        (resident_id,),
    ).fetchall()
    for application in applications:
        paths.extend(_unique_paths(application["person_photo_path"], application["aadhaar_photo_path"]))
    return _unique_paths(*paths)


def _release_claim(table: str, record_id: str, claim: str) -> None:
    with database.transaction() as connection:
        connection.execute(
            f"UPDATE {table} SET retention_purging_at = NULL "
            "WHERE id = ? AND retention_purging_at = ?",
            (record_id, claim),
        )


def _remove_files(paths: list[str], kind: str) -> bool:
    try:
        for path in paths:
            remove_encrypted_document(path)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError):
        logger.exception("Retention cleanup could not remove a %s document.", kind)
        return False
    return True


def _purge_resident(resident_id: str, cutoff: str, now: datetime) -> int:
    stale_claim = (now - PURGE_CLAIM_TIMEOUT).isoformat()
    claim = now.isoformat()
    with database.transaction() as connection:
        claimed = connection.execute(
            "UPDATE residents SET retention_purging_at = ? "
            "WHERE id = ? AND checked_out_at <= ? "
            "AND (retention_purging_at IS NULL OR retention_purging_at <= ?)",
            (claim, resident_id, cutoff, stale_claim),
        )
        if claimed.rowcount != 1:
            return 0
        paths = _resident_paths(connection, resident_id)
    if not _remove_files(paths, "resident"):
        _release_claim("residents", resident_id, claim)
        return -1

    with database.transaction() as connection:
        resident = connection.execute(
            "SELECT id FROM residents WHERE id = ? AND checked_out_at <= ? AND retention_purging_at = ?",
            (resident_id, cutoff, claim),
        ).fetchone()
        if not resident:
            return 0
        applications = connection.execute(
            "SELECT id, invite_id FROM registration_applications WHERE resident_id = ?",
            (resident_id,),
        ).fetchall()
        bookings = connection.execute(
            "SELECT id FROM bookings WHERE resident_id = ?",
            (resident_id,),
        ).fetchall()
        documents = connection.execute(
            "SELECT id FROM documents WHERE resident_id = ?",
            (resident_id,),
        ).fetchall()
        related_ids = [
            resident_id,
            *(row["id"] for row in applications),
            *(row["invite_id"] for row in applications),
            *(row["id"] for row in bookings),
            *(row["id"] for row in documents),
        ]
        placeholders = ",".join("?" for _ in related_ids)
        connection.execute(
            f"DELETE FROM audit_log WHERE entity_id IN ({placeholders})",
            related_ids,
        )
        connection.execute("DELETE FROM documents WHERE resident_id = ?", (resident_id,))
        connection.execute("DELETE FROM bookings WHERE resident_id = ?", (resident_id,))
        connection.execute("DELETE FROM registration_applications WHERE resident_id = ?", (resident_id,))
        for application in applications:
            connection.execute("DELETE FROM registration_invites WHERE id = ?", (application["invite_id"],))
        deleted = connection.execute(
            "DELETE FROM residents WHERE id = ? AND checked_out_at <= ? AND retention_purging_at = ?",
            (resident_id, cutoff, claim),
        )
        return int(deleted.rowcount == 1)


def _purge_application(application_id: str, cutoff: str, now: datetime) -> int:
    stale_claim = (now - PURGE_CLAIM_TIMEOUT).isoformat()
    claim = now.isoformat()
    with database.transaction() as connection:
        claimed = connection.execute(
            "UPDATE registration_applications SET retention_purging_at = ? "
            "WHERE id = ? AND status = 'pending' AND resident_id IS NULL AND submitted_at <= ? "
            "AND (retention_purging_at IS NULL OR retention_purging_at <= ?)",
            (claim, application_id, cutoff, stale_claim),
        )
        if claimed.rowcount != 1:
            return 0
        paths = _application_paths(connection, application_id)
    if not _remove_files(paths, "registration"):
        _release_claim("registration_applications", application_id, claim)
        return -1

    with database.transaction() as connection:
        application = connection.execute(
            "SELECT id, invite_id FROM registration_applications WHERE id = ? AND status = 'pending' "
            "AND resident_id IS NULL AND submitted_at <= ? AND retention_purging_at = ?",
            (application_id, cutoff, claim),
        ).fetchone()
        if not application:
            return 0
        connection.execute(
            "DELETE FROM audit_log WHERE entity_id IN (?, ?)",
            (application_id, application["invite_id"]),
        )
        deleted = connection.execute(
            "DELETE FROM registration_applications WHERE id = ? AND retention_purging_at = ?",
            (application_id, claim),
        )
        if deleted.rowcount != 1:
            return 0
        connection.execute("DELETE FROM registration_invites WHERE id = ?", (application["invite_id"],))
        return 1


def purge_expired_records(now: datetime | None = None) -> dict[str, int | str]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cutoff = _three_months_before(current).isoformat()
    stale_claim = (current - PURGE_CLAIM_TIMEOUT).isoformat()
    with database.read_connection() as connection:
        residents = [
            row["id"]
            for row in connection.execute(
                "SELECT id FROM residents WHERE checked_out_at <= ? "
                "AND (retention_purging_at IS NULL OR retention_purging_at <= ?) "
                "ORDER BY checked_out_at LIMIT ?",
                (cutoff, stale_claim, RETENTION_BATCH_SIZE),
            ).fetchall()
        ]
        applications = [
            row["id"]
            for row in connection.execute(
                "SELECT id FROM registration_applications WHERE status = 'pending' AND resident_id IS NULL "
                "AND submitted_at <= ? AND (retention_purging_at IS NULL OR retention_purging_at <= ?) "
                "ORDER BY submitted_at LIMIT ?",
                (cutoff, stale_claim, RETENTION_BATCH_SIZE),
            ).fetchall()
        ]

    resident_results = [_purge_resident(resident_id, cutoff, current) for resident_id in residents]
    application_results = [
        _purge_application(application_id, cutoff, current) for application_id in applications
    ]
    return {
        "deleted_residents": sum(result == 1 for result in resident_results),
        "deleted_pending_applications": sum(result == 1 for result in application_results),
        "cleanup_failures": sum(result == -1 for result in [*resident_results, *application_results]),
        "cutoff": cutoff,
    }
