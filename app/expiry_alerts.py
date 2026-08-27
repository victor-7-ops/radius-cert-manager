"""Certificate expiry alerting.

There's no scheduler/cron in this app (handoff never asked for one —
everything runs synchronously inside a request). So this isn't a
background job: check_and_alert() runs opportunistically, called from
the health page each time a Super Admin loads it. That's "on standby"
until it's wired to something with a real clock (a cron hitting
/health, or a proper scheduled task) — the alerting logic itself is
complete and Slack-ready today; it just needs a periodic trigger and a
Slack incoming-webhook URL in ALERT_WEBHOOK_URL to actually fire.

One alert per newly-crossed-threshold cert, not one per check: each
cert's expiry_alert_sent_at is set the first time it's included in an
alert, so re-running the check (e.g. every /health load) only ever
alerts about certs that just crossed into the window since the last
check — not the same ones over and over.
"""

from __future__ import annotations

import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import Certificate, CertStatus

DEFAULT_WARNING_DAYS = 7


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def check_and_alert(session: Session, alert_fn, warning_days: int = DEFAULT_WARNING_DAYS) -> list[Certificate]:
    """Finds active certs expiring within warning_days that haven't
    already been alerted on, sends ONE alert covering all of them (not
    one per cert — a batch of 10 renewals due together shouldn't be 10
    separate pings), marks them alerted, and returns the list. Returns
    [] (and never calls alert_fn) when there's nothing new to report."""
    now = _now()
    cutoff = now + datetime.timedelta(days=warning_days)

    # Filtering expires_at in Python rather than in SQL: SQLite stores
    # these naive (no tzinfo) and compares them as strings, and every
    # other date comparison in this codebase (dashboard, crl_health)
    # does the same fetch-then-filter-in-Python dance for exactly that
    # reason — this table is small enough that it's not worth the risk
    # of a subtle off-by-timezone SQL comparison bug.
    candidates = session.scalars(
        select(Certificate).where(
            Certificate.status == CertStatus.active,
            Certificate.expiry_alert_sent_at.is_(None),
        )
    ).all()
    # Also catches already-expired-but-still-active rows (handoff
    # §5.2's computed "expired" status) — those need the alert at least
    # as much as ones still ticking down.
    due = sorted((c for c in candidates if _aware(c.expires_at) <= cutoff), key=lambda c: c.expires_at)
    if not due:
        return []

    lines = [f"{len(due)} certificate{'s' if len(due) != 1 else ''} expiring within {warning_days} days:"]
    for c in due:
        days_left = (_aware(c.expires_at) - now).days
        when = f"in {days_left}d" if days_left >= 0 else "EXPIRED"
        who = f" ({c.employee_name})" if c.employee_name else ""
        lines.append(f"  {c.cn}{who} — {when}")
    alert_fn("\n".join(lines))

    for c in due:
        c.expiry_alert_sent_at = now
    session.commit()
    return due
