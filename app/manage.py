import argparse
import getpass
import re
import sqlite3
import uuid
from datetime import datetime, timezone

from app import database
from app.security import hash_password, password_policy_error


def create_user(role: str, owner_username: str | None = None) -> None:
    database.initialize_database()
    username = input("Staff username: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
        raise SystemExit("Use 3-40 letters, numbers, dots, underscores, or hyphens for the username.")
    password = getpass.getpass("Password (8+ characters with upper/lowercase, number, and special character): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords must match.")
    policy_error = password_policy_error(password)
    if policy_error:
        raise SystemExit(policy_error)

    staff_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with database.transaction() as connection:
            existing_users = connection.execute("SELECT COUNT(*) FROM staff").fetchone()[0]
            if existing_users == 0 and role != "admin":
                raise SystemExit("The first staff account must be an admin.")
            if role == "admin":
                owner_id = staff_id
            else:
                admin_rows = connection.execute(
                    "SELECT id, username, owner_id FROM staff WHERE role = 'admin' ORDER BY username"
                ).fetchall()
                if owner_username:
                    owner = next((row for row in admin_rows if row["username"].casefold() == owner_username.casefold()), None)
                    if not owner:
                        raise SystemExit("Choose an existing admin username for --owner.")
                elif len({row["owner_id"] for row in admin_rows}) == 1:
                    owner = admin_rows[0]
                else:
                    raise SystemExit("Specify --owner with the admin username whose data this staff account will access.")
                owner_id = owner["owner_id"]
            connection.execute(
                "INSERT INTO staff (id, owner_id, username, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (staff_id, owner_id, username, hash_password(password), role, created_at),
            )
            database.write_audit(
                connection,
                None,
                "staff.bootstrap" if existing_users == 0 else "staff.cli_create",
                "staff",
                staff_id,
                {"username": username, "role": role},
            )
    except sqlite3.IntegrityError as error:
        raise SystemExit("That staff username already exists.") from error
    print(f"Created {role} account: {username}")


def reset_password(username: str) -> None:
    database.initialize_database()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
        raise SystemExit("Use 3-40 letters, numbers, dots, underscores, or hyphens for the username.")
    password = getpass.getpass("New password (8+ characters with upper/lowercase, number, and special character): ")
    confirmation = getpass.getpass("Confirm new password: ")
    if password != confirmation:
        raise SystemExit("Passwords must match.")
    policy_error = password_policy_error(password)
    if policy_error:
        raise SystemExit(policy_error)

    password_hash = hash_password(password)
    with database.transaction() as connection:
        staff = connection.execute("SELECT id FROM staff WHERE username = ?", (username,)).fetchone()
        if not staff:
            raise SystemExit("No staff account with that username exists.")
        connection.execute("UPDATE staff SET password_hash = ? WHERE id = ?", (password_hash, staff["id"]))
        connection.execute("DELETE FROM sessions WHERE staff_id = ?", (staff["id"],))
        database.write_audit(
            connection,
            None,
            "staff.cli_password_reset",
            "staff",
            staff["id"],
            {"username": username},
        )
    print(f"Password reset for staff account: {username}")


def create_platform_admin() -> None:
    database.initialize_database()
    username = input("Developer username: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", username):
        raise SystemExit("Use 3-40 letters, numbers, dots, underscores, or hyphens for the username.")
    password = getpass.getpass("Password (8+ characters with upper/lowercase, number, and special character): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords must match.")
    policy_error = password_policy_error(password)
    if policy_error:
        raise SystemExit(policy_error)

    account_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    try:
        with database.transaction() as connection:
            connection.execute(
                "INSERT INTO platform_accounts (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (account_id, username, hash_password(password), now),
            )
            database.write_audit(
                connection,
                None,
                "platform.account_create",
                "platform_account",
                account_id,
                {"username": username},
            )
    except sqlite3.IntegrityError as error:
        raise SystemExit("That developer username already exists.") from error
    print(f"Created developer account: {username}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Haven Hostel staff accounts.")
    parser.add_argument(
        "command",
        choices=["create-admin", "create-warden", "create-staff", "reset-password", "create-platform-admin"],
    )
    parser.add_argument("--role", choices=["admin", "warden"], default="warden")
    parser.add_argument("--owner", help="Admin username whose data this staff account will access")
    parser.add_argument("--username", help="Staff username to reset")
    arguments = parser.parse_args()
    if arguments.command == "create-platform-admin":
        create_platform_admin()
        return
    if arguments.command == "reset-password":
        username = arguments.username or input("Staff username: ").strip()
        reset_password(username)
        return
    role = {"create-admin": "admin", "create-warden": "warden", "create-staff": arguments.role}[arguments.command]
    create_user(role, arguments.owner)


if __name__ == "__main__":
    main()