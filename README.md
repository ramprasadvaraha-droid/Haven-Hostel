# Haven Hostel

Haven is a same-origin FastAPI app for hostel check-in/check-out, room and bed occupancy, and payment tracking. The owner can configure multiple hostels, numbered floors, and any number of rooms per floor; each room can have 1–20 beds. The backend uses SQLite, Argon2 password hashes, expiring HTTP-only staff sessions, CSRF checks on changes, field-level encryption for names/mobile/Aadhaar, encrypted image files, an audit log, and encrypted backup archives.

## Local setup

Requires Python 3.11 or newer. The current workspace was checked with Python 3.14.7.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m app.setup
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

`app.setup` creates a private `.env` with a new encryption key. `.env` and `data/` are git-ignored. Open <http://127.0.0.1:8000>; on a fresh local install the landing page prompts you to create the first admin account. This one-time signup is available only from a loopback address and closes after the first account is created. No default credentials are created. Alternatively, bootstrap the first admin in a trusted terminal with `python -m app.manage create-admin`. Create additional staff from the admin-only `POST /api/staff` endpoint or with `python -m app.manage create-warden` on the trusted host.

Each admin owns a separate hostel workspace. Staff accounts created by an admin share only that admin's workspace; separate admin accounts cannot see each other's residents, rooms, documents, or audit history. On upgrade, existing data stays together under the current primary admin. To create additional independent owners, use `python -m app.manage create-admin`. To create a warden from the trusted host when there is more than one owner, specify `--owner ADMIN_USERNAME`.

On upgrade from the original fixed-room version, the app migrates the existing rooms 101–108 to `Hostel 1`, `1st Floor`, with four beds each. Existing resident room and bed assignments are preserved. After upgrade, use **Rooms → Add hostel → Add floor → Add room** to configure additional properties and capacities. Admins can delete vacant rooms or hostels. Rooms with current residents cannot be deleted; hostels with checked-in residents cannot be deleted. Deletion removes them from active availability while retaining past stay/audit history.

Admins can read the audit log and manage staff. Admins and wardens can manage resident stays and payments. The API rejects writes without the session CSRF token; session cookies are HTTP-only and SameSite=Strict. Login failures are rate-limited and recorded without passwords.

## Data protection

Names, mobile numbers, and Aadhaar numbers are Fernet-encrypted before they are written to SQLite. Aadhaar is optional and the API returns only its last four digits. Uploaded JPEG, PNG, and WebP images are signature-checked, size-limited to 5 MB, encrypted before disk storage, and only downloadable to authenticated staff. Downloads are audited and sent as attachments with no-store headers. Audit records never include Aadhaar values, passwords, or document contents.

SQLite also contains operational metadata such as room/bed assignment, dates, and payment balances; it is not a SQLCipher-encrypted database. Protect the host volume with OS/disk encryption, restrict access to the service account, use HTTPS, and keep the encryption key separate from backups in production. Losing the encryption key makes resident identifiers, documents, and encrypted backups unrecoverable.

## Backups

Run a backup manually with:

```powershell
python -m app.backup
```

The command uses SQLite's online backup API, includes encrypted documents, encrypts the complete archive with the app key, and retains the newest 14 snapshots under `data/backups/`. Schedule this command daily with Windows Task Scheduler (program: `.venv\Scripts\python.exe`, arguments: `-m app.backup`, start-in: the project directory). Store a separate protected copy of the encryption key and periodically test recovery on an isolated host.

## Tests

```powershell
python -m pytest
```

The tests use temporary data and keys. They cover authentication and role checks, CSRF rejection, check-in with encrypted documents, unique bed assignment, month-end payment dates, payment updates, check-out/bed release, audit events, and encrypted backups.

## Production boundary

The generated local `.env` sets `HOSTEL_COOKIE_SECURE=false` so localhost HTTP works. Before any network deployment, set `HOSTEL_COOKIE_SECURE=true`, serve only behind HTTPS, put keys in a secret manager, set restrictive host/database/document/backup permissions, schedule and test backups, and review local privacy/retention requirements for Aadhaar. This repo does not configure cloud hosting, monitoring, or WhatsApp Business API delivery.

On Vercel, the default SQLite database and files live under `/tmp` and are temporary. Do not use that storage for real multi-owner data. Configure a persistent Postgres `DATABASE_URL` and `BLOB_READ_WRITE_TOKEN` for encrypted resident documents before production use; migrate existing SQLite data with `python -m app.migrate_to_postgres`. The Vercel project needs those values configured in its Production environment.