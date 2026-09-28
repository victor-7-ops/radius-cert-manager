"""Report subsidiary values that don't match db.SUBSIDIARIES
(HANDOFF-COMPLIANCE.md §2). Read-only — reports, never auto-corrects, so a
near-miss like "Lezzgo boracay" vs "Lezzgo Boracay" is a human decision:
guessing which existing value someone meant risks silently re-scoping
their access.

Covers every table with a subsidiary dimension: certificates, sites,
admins.subsidiary_scope, audit_log.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from app import db
from app.main import create_app


def _mismatches(session, model, column) -> dict[str, int]:
    counts: dict[str, int] = {}
    for (value,) in session.execute(select(column).where(column.is_not(None))).all():
        if value and value not in db.SUBSIDIARIES:
            counts[value] = counts.get(value, 0) + 1
    return counts


def main() -> int:
    app = create_app()
    session = app.state.get_db_session()

    checks = [
        ("certificates.subsidiary", db.Certificate, db.Certificate.subsidiary),
        ("sites.subsidiary", db.Site, db.Site.subsidiary),
        ("admins.subsidiary_scope", db.Admin, db.Admin.subsidiary_scope),
        ("audit_log.subsidiary", db.AuditLog, db.AuditLog.subsidiary),
    ]

    total = 0
    for label, model, column in checks:
        mismatches = _mismatches(session, model, column)
        if not mismatches:
            print(f"{label}: no mismatches")
            continue
        print(f"{label}: {sum(mismatches.values())} row(s) across {len(mismatches)} unknown value(s)")
        for value, count in sorted(mismatches.items(), key=lambda kv: -kv[1]):
            print(f"  {value!r}: {count}")
        total += sum(mismatches.values())

    print(f"\ntotal mismatched rows: {total}")
    print("nothing was changed — this is a report only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
