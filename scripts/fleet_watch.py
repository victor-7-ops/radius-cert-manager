"""Entry point for a systemd timer: evaluate every site and alert on any
status change (HANDOFF-FLEET.md §5.1). Staleness detection must not
depend on someone having the /health page open — "nobody opened the
dashboard, so nobody noticed Boracay died" is exactly the failure mode
this script exists to prevent. Run it on an interval comfortably shorter
than the shortest site's checkin_interval_seconds.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app


def main() -> int:
    app = create_app()
    app.state.run_fleet_watch()
    # Only sent after a successful run — a heartbeat that fires even when
    # the run itself failed would defeat the point (handoff §8.2).
    app.state.send_heartbeat()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
