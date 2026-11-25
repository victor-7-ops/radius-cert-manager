"""Entry point for a systemd timer: run the synthetic auth canary
against every configured site, then reuse fleet_watch's existing edge-
triggered alerting (handoff task O2) -- a canary failure folds into
fleet_health.evaluate_site's status, so this needs no alerting logic of
its own beyond what app/fleet_watch.py already does.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select

from app import ap_secrets, canary, db
from app.main import create_app


def main() -> int:
    app = create_app()
    settings = app.state.settings
    session = app.state.get_db_session()

    sites = session.scalars(
        select(db.Site).where(db.Site.is_active.is_(True), db.Site.canary_cert_id.is_not(None))
    ).all()

    for site in sites:
        ap = session.scalar(
            select(db.AccessPoint).where(
                db.AccessPoint.site_id == site.id,
                db.AccessPoint.name == canary.HUB_CANARY_AP_NAME,
                db.AccessPoint.is_active.is_(True),
            )
        )
        if ap is None:
            db.audit(
                session, actor="system", action="canary_probe_skipped", target=site.radius_cn,
                detail=f"no {canary.HUB_CANARY_AP_NAME!r} AccessPoint configured for this site",
                subsidiary=site.subsidiary, site_id=site.id,
            )
            session.commit()
            continue

        # ap.ip_address is the HUB's own IP (that's what makes it a valid
        # NAS client entry on the site's clients.conf, task M) -- the
        # probe's destination is the site's own FreeRADIUS, reachable at
        # crl_push_host (same host app/crl_push.py already SSHes into)
        # or radius_cn as a fallback for the primary site, which is
        # seeded directly from RADIUS_HOST and so is itself a resolvable
        # hostname, not just a label.
        secret = ap_secrets.decrypt_secret(ap.secret_ciphertext, settings.pki_path)
        target_host = site.crl_push_host or site.radius_cn
        result = canary.run_probe(site, settings.pki_path, secret, server_ip=target_host)
        canary.record_probe_result(session, site, result)

    revoked_sites = session.scalars(
        select(db.Site).where(db.Site.is_active.is_(True), db.Site.revoked_canary_cert_id.is_not(None))
    ).all()

    for site in revoked_sites:
        ap = session.scalar(
            select(db.AccessPoint).where(
                db.AccessPoint.site_id == site.id,
                db.AccessPoint.name == canary.HUB_CANARY_AP_NAME,
                db.AccessPoint.is_active.is_(True),
            )
        )
        if ap is None:
            db.audit(
                session, actor="system", action="revoked_canary_probe_skipped", target=site.radius_cn,
                detail=f"no {canary.HUB_CANARY_AP_NAME!r} AccessPoint configured for this site",
                subsidiary=site.subsidiary, site_id=site.id,
            )
            session.commit()
            continue

        secret = ap_secrets.decrypt_secret(ap.secret_ciphertext, settings.pki_path)
        target_host = site.crl_push_host or site.radius_cn
        result = canary.run_revoked_probe(site, settings.pki_path, secret, server_ip=target_host)
        canary.record_revoked_probe_result(session, site, result)

    # Reuses fleet_watch's own edge-triggered dedup (Site.last_alerted_status)
    # -- a canary-caused status change alerts exactly once, same as any
    # other fleet_health signal, via the webhook already wired in O1.
    app.state.run_fleet_watch()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
