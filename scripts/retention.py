"""Entry point for a systemd timer: run data retention/minimisation
(HANDOFF-COMPLIANCE.md §1). Following scripts/fleet_watch.py's pattern —
a single pass per invocation, no in-process scheduler.

--dry-run reports what would change and touches nothing; this is what
gets shown to the DPO before the real thing is ever scheduled. Without
the flag, it applies. Any *_retention_days left unset in the environment
means that category is a no-op either way.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app
from app import retention


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be minimised/redacted/deleted; change nothing",
    )
    args = parser.parse_args()

    app = create_app()
    settings = app.state.settings
    session = app.state.get_db_session()

    report = retention.run_retention(session, settings, dry_run=args.dry_run)

    would = args.dry_run
    print(f"certificates {'would be minimised' if would else 'minimised'}: {report.cert_count}")
    print(f"audit rows {'would have detail redacted' if would else 'had detail redacted'}: {report.audit_count}")
    print(f"admin sessions {'would be deleted' if would else 'deleted'}: {report.session_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
