"""The renewal campaign (HANDOFF-LIFECYCLE.md §2) — client certs have no
automated re-enrolment (no endpoint management platform), so once a year
the whole fleet has to be re-enrolled by hand. This is the work-queue
logic behind that: which certs need it, and which have already been
renewed. Pure functions over plain values, unit-testable like
app/fleet_health.py and app/crl_health.py.
"""

from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass

from app import db

WINDOWS = (30, 60, 90)


class RenewalProgress(str, enum.Enum):
    outstanding = "outstanding"
    done = "done"
    retired = "retired"


def aware(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def in_cohort(cert: db.Certificate, window_days: int | None, now: datetime.datetime) -> bool:
    """window_days=None means the "already expired" bucket. A retired
    cert stays out of every window — it left the queue on purpose."""
    if cert.cert_type != "client" or cert.status != db.CertStatus.active:
        return False
    if cert.retired_at is not None:
        return False
    days_remaining = (aware(cert.expires_at) - now).total_seconds() / 86400
    if window_days is None:
        return days_remaining < 0
    return 0 <= days_remaining <= window_days


def progress_for(cert: db.Certificate, successor: db.Certificate | None, window_days: int | None, now: datetime.datetime) -> RenewalProgress:
    """A cohort cert is `done` once a successor exists that's active and
    not itself due soon — otherwise a same-day reissue-then-immediately-
    expiring chain would count as "handled" when it isn't
    (HANDOFF-LIFECYCLE.md §2.2). `window_days=None` (the "already
    expired" bucket) uses the smallest standard window as the successor's
    bar, since there's no forward window to compare against."""
    if cert.retired_at is not None:
        return RenewalProgress.retired
    if successor is None or successor.status != db.CertStatus.active:
        return RenewalProgress.outstanding
    bar_days = window_days if window_days is not None else min(WINDOWS)
    days_remaining = (aware(successor.expires_at) - now).total_seconds() / 86400
    if days_remaining > bar_days:
        return RenewalProgress.done
    return RenewalProgress.outstanding


@dataclass
class CohortRow:
    certificate: db.Certificate
    successor: db.Certificate | None
    progress: RenewalProgress
    days_remaining: float
