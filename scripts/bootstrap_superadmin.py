"""One-time CLI bootstrap of the first Super Admin (handoff §5.7).

Refuses to run if an admin already exists. No default password in source.

Usage:
    python -m scripts.bootstrap_superadmin --username alice
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth, db
from app.config import load_settings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    args = parser.parse_args()

    settings = load_settings()
    engine = db.make_engine(str(settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    if session.query(db.Admin).count() > 0:
        print("Refusing to bootstrap: an admin already exists.", file=sys.stderr)
        return 1

    password = getpass.getpass("Set initial password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords did not match.", file=sys.stderr)
        return 1
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 1

    admin = db.Admin(
        username=args.username,
        password_hash=auth.hash_password(password),
        role=db.AdminRole.super_admin,
        must_change_password=False,
        created_by="bootstrap",
    )
    session.add(admin)
    db.audit(session, actor="bootstrap", action="create_admin", target=args.username)
    session.commit()
    print(f"Super Admin '{args.username}' created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
