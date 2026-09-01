"""Scheduled fleet evaluation + alerting (HANDOFF-FLEET.md §5.1). Driven
by scripts/fleet_watch.py on a systemd timer — staleness alerts must not
depend on someone having the /health page open (§5.1's whole point).

TRAP (§5.1): a site stuck at WARN/CRITICAL/SILENT must fire exactly one
alert, not one per scheduler run for as long as it stays that way.
Site.last_alerted_status makes this edge-triggered: alert only on a
transition into a worse status, and again on recovery back to OK so a
regression after a fix is still visible.
"""

from __future__ import annotations

import datetime

from sqlalchemy.orm import Session

from app import db, fleet_health


def check_and_alert(
    session: Session,
    alert_fn,
    now: datetime.datetime | None = None,
) -> list[fleet_health.SiteHealth]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    results = fleet_health.evaluate_fleet(session, now)

    changed = []
    for health in results:
        site = session.get(db.Site, health.site_id)
        previous = site.last_alerted_status or fleet_health.SiteStatus.ok.value
        if health.status.value != previous:
            changed.append(health)
            site.last_alerted_status = health.status.value

    if changed:
        # One message for the whole run, not one per site (§5.1 TRAP —
        # the same Slack-silently-swallows-text/plain lesson from
        # app/expiry_alerts.py applies to how this message is shaped,
        # even though the JSON-body fix itself lives in the shared
        # alert_fn this reuses).
        lines = [f"{h.name} ({h.radius_cn}): {h.status.value}" for h in changed]
        alert_fn("Fleet status changed:\n" + "\n".join(lines))

    session.commit()
    return changed
