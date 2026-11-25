"""Entry point for a systemd timer: a daily fleet-status summary
(handoff task O2's "also worth adding" list). fleet_watch is edge-
triggered on purpose -- correct for noise, but it means a site broken
Monday goes silent by Tuesday. This always fires, once a day.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app


def main() -> int:
    app = create_app()
    app.state.send_daily_digest()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
