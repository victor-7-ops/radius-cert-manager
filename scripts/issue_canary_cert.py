"""One-time per-site setup for the synthetic auth canary (handoff task
O2). Run by hand once per site -- this is not a repeated workflow, so it
gets a script instead of an admin UI form.

Usage:
    python -m scripts.issue_canary_cert <site_radius_cn> <subsidiary_code> <network_role_code>

Also reminds you of the other one-time step this depends on: an
AccessPoint row named "hub-canary" on that site, with the hub's own
reachable IP, so the site's clients.conf (task M) trusts the hub as a
NAS when it runs the probe.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from app import canary, db
from app.config import load_settings
from app.main import create_app


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 1
    radius_cn, subsidiary_code, network_role_code = sys.argv[1:4]

    settings = load_settings()
    app = create_app(settings)
    session = app.state.get_db_session()

    site = session.scalar(select(db.Site).where(db.Site.radius_cn == radius_cn))
    if site is None:
        print(f"no site with radius_cn={radius_cn!r}")
        return 1
    if site.canary_cert_id:
        print(f"{radius_cn} already has a canary cert (certificate id {site.canary_cert_id}) — nothing to do")
        return 0

    subsidiary = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == subsidiary_code))
    if subsidiary is None:
        print(f"no subsidiary with code={subsidiary_code!r}")
        return 1
    role = session.scalar(
        select(db.NetworkRole).where(
            db.NetworkRole.subsidiary_id == subsidiary.id, db.NetworkRole.code == network_role_code,
        )
    )
    if role is None:
        print(f"no network role with code={network_role_code!r} under subsidiary {subsidiary_code!r}")
        return 1

    from app import pki

    inter_cert = pki.load_cert_pem(settings.pki_path / "intermediate.crt")
    inter_key = pki.load_key_pem(settings.pki_path / "private" / "intermediate.key")

    cert = canary.issue_canary_certificate(
        session, settings.pki_path, inter_cert, inter_key, site,
        subsidiary_id=subsidiary.id, network_role_id=role.id, issued_by="cli:issue_canary_cert",
    )

    print(f"issued canary cert serial={cert.serial} cn={cert.cn}")
    print(f"key+cert written to {canary.canary_dir(settings.pki_path, site)}")
    print()
    print("REMAINING ONE-TIME STEP (not automated by this script):")
    print(f"  Add an AccessPoint row named {canary.HUB_CANARY_AP_NAME!r} for this site,")
    print("  with ip_address = the hub's own IP as this site's FreeRADIUS sees it,")
    print("  so clients.conf (task M) trusts the hub as a NAS when canary_probe.py runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
