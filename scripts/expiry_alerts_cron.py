"""Entry point for a systemd timer: fire certificate expiry alerts
(handoff task N item 1). app/expiry_alerts.py has been complete and
tested since before this file existed, but its only caller was the
/health page ("opportunistic, not scheduled") -- nobody alerts if nobody
happens to load that page. This gives it a real clock.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app


def main() -> int:
    app = create_app()
    app.state.check_expiry_alerts()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
