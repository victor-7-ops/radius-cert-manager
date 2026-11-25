"""One-time per-site setup for the synthetic auth canary (handoff task
O2). Run by hand once per site -- this is not a repeated workflow, so it
gets a script instead of an admin UI form.

Usage:
    python -m scripts.issue_canary_cert <site_radius_cn> <subsidiary_code> <network_role_code> [--revoked]

--revoked issues the P1 revoked-cert canary instead (25 Nov 2026): a cert
revoked immediately at issuance, used to prove check_crl is still enforcing
revocation rather than that auth itself works.

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
    args = [a for a in sys.argv[1:] if a != "--revoked"]
    revoked = "--revoked" in sys.argv[1:]
    if len(args) != 3:
        print(__doc__)
        return 1
    radius_cn, subsidiary_code, network_role_code = args

    settings = load_settings()
    app = create_app(settings)
    session = app.state.get_db_session()

    site = session.scalar(select(db.Site).where(db.Site.radius_cn == radius_cn))
    if site is None:
        print(f"no site with radius_cn={radius_cn!r}")
        return 1
    if revoked and site.revoked_canary_cert_id:
        print(f"{radius_cn} already has a revoked canary cert (certificate id {site.revoked_canary_cert_id}) — nothing to do")
        return 0
    if not revoked and site.canary_cert_id:
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

    issue_fn = canary.issue_revoked_canary_certificate if revoked else canary.issue_canary_certificate
    dir_fn = canary.revoked_canary_dir if revoked else canary.canary_dir

    cert = issue_fn(
        session, settings.pki_path, inter_cert, inter_key, site,
        subsidiary_id=subsidiary.id, network_role_id=role.id, issued_by="cli:issue_canary_cert",
    )

    label = "revoked canary" if revoked else "canary"
    print(f"issued {label} cert serial={cert.serial} cn={cert.cn}")
    print(f"key+cert written to {dir_fn(settings.pki_path, site)}")
    print()
    print("REMAINING ONE-TIME STEP (not automated by this script):")
    print(f"  Add an AccessPoint row named {canary.HUB_CANARY_AP_NAME!r} for this site,")
    print("  with ip_address = the hub's own IP as this site's FreeRADIUS sees it,")
    print("  so clients.conf (task M) trusts the hub as a NAS when canary_probe.py runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
