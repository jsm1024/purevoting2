"""Staff-account setup script (no account API, threat-model O1). Runs before Core in the bootstrap order.

    python -m app.scripts.create_staff --username admin1 --org org_commission --role admin
    (password from the STAFF_PASSWORD environment variable, or asked interactively)

Accounts that already exist are left unchanged. Run it with the DB connection of Core (DATABASE_URL).
"""
import argparse
import getpass
import os
import re
import sys

from sqlalchemy import text

from app.auth import hash_password
from app.db import get_engine
from app.ids import ulid


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--username", required=True)
    p.add_argument("--org", required=True, help="org_id, e.g. org_commission")
    p.add_argument("--role", required=True, choices=["admin", "approver", "auditor"])
    a = p.parse_args(argv)
    if not re.fullmatch(r"org_[a-z0-9_]{2,32}", a.org):
        p.error("--org must look like org_commission")
    password = os.environ.get("STAFF_PASSWORD") or getpass.getpass("password: ")
    if len(password) < 8:
        p.error("password must have at least 8 characters")
    with get_engine().begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM credential.staff_users WHERE username = :u"),
                              {"u": a.username}).first()
        if exists:
            print(f"{a.username}: already exists, unchanged")
            return 0
        conn.execute(text("INSERT INTO credential.staff_users (user_id, username, password_hash, org_id, role) "
                          "VALUES (:id, :u, :p, :o, :r)"),
                     {"id": ulid("usr"), "u": a.username, "p": hash_password(password), "o": a.org, "r": a.role})
    print(f"{a.username}: created ({a.role}, {a.org})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
