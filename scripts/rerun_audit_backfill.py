"""Deliberately re-run the audit_log subsidiary backfill
(HANDOFF-COMPLIANCE.md §6). init_db() only runs it once (guarded by a
MigrationFlag row) so a normal boot doesn't re-scan the whole audit_log
table forever — use this after correcting a certificate's subsidiary,
so audit rows that reference it can pick up the fix.

Deletes the flag row, then runs the backfill immediately (rather than
waiting for the next restart to notice the flag is gone).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app
from app import db


def main() -> int:
    app = create_app()
    engine = app.state.get_db_session().get_bind()

    with db.Session(engine) as session:
        flag = session.get(db.MigrationFlag, "audit_log_subsidiary_backfill")
        if flag is not None:
            session.delete(flag)
            session.commit()

    updated = db.backfill_audit_log_subsidiary(engine)
    db.run_once(engine, "audit_log_subsidiary_backfill", lambda: None)
    print(f"backfilled {updated} audit_log row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
