"""Entry point for a systemd timer / cron job: regenerate + push the CRL.

Handoff §8.3: run on a schedule comfortably shorter than CRL_VALIDITY_DAYS
(CRL_REGEN_HOURS, default daily), plus immediately after every
revoke/suspend (main.py calls the same path inline on those routes).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.main import create_app


def main() -> int:
    app = create_app()
    app.state.regenerate_and_push_crl()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
