"""Per-site fleet status derivation (HANDOFF-FLEET.md §5). Pure functions
over plain values, tested in isolation like app/crl_health.py — a status
that reads OK when a site actually died is exactly the failure this
feature exists to prevent, so the logic deserves the same isolation.
"""

from __future__ import annotations

import datetime
import enum
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, crl_health, db

CRITICAL_CERT_DAYS_REMAINING = 14
SILENT_MISSED_INTERVALS = 3
WARN_MISSED_INTERVALS = 1


class SiteStatus(str, enum.Enum):
    ok = "OK"
    warn = "WARN"
    critical = "CRITICAL"
    silent = "SILENT"


@dataclass
class SiteHealth:
    site_id: str
    name: str
    radius_cn: str
    subsidiary: str | None
    status: SiteStatus
    last_seen_at: datetime.datetime | None
    minutes_since_checkin: float | None
    crl_hours_remaining: float | None
    crl_is_current: bool | None
    server_cert_days_remaining: float | None
    freeradius_ok: bool | None
    agent_version: str | None


def _aware(dt: datetime.datetime | None) -> datetime.datetime | None:
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=datetime.timezone.utc)


def evaluate_site(
    site: db.Site,
    server_cert: db.Certificate | None,
    crl_freshness: "crl_health.HostCrlFreshness | None",
    now: datetime.datetime | None = None,
) -> SiteHealth:
    """Derives one status for a site from what the hub actually knows —
    absence of a recent check-in is itself a signal, not just missing
    data (§5's whole reason for existing).

    crl_freshness is this SITE's own reported CRL state (handoff task N
    item 2), not the hub's -- a site that missed a checkin and is still
    running last week's CRL must show as critical on its own, not get
    averaged into "the hub's CRL is fresh" like the old
    crl_last_generated_at parameter did."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    last_seen = _aware(site.last_seen_at)

    minutes_since_checkin = (
        (now - last_seen).total_seconds() / 60 if last_seen is not None else None
    )
    missed_intervals = (
        minutes_since_checkin / (site.checkin_interval_seconds / 60)
        if minutes_since_checkin is not None and site.checkin_interval_seconds > 0
        else None
    )

    crl_hours_remaining = crl_freshness.hours_remaining if crl_freshness else None
    crl_is_critical = crl_freshness.is_critical if crl_freshness else True

    server_cert_days_remaining = None
    if server_cert is not None:
        server_cert_days_remaining = (
            _aware(server_cert.expires_at) - now
        ).total_seconds() / 86400

    freeradius_ok = site.last_reported_freeradius_ok

    if missed_intervals is None or missed_intervals > SILENT_MISSED_INTERVALS:
        status = SiteStatus.silent
    elif (
        crl_is_critical
        or (
            server_cert_days_remaining is not None
            and server_cert_days_remaining <= CRITICAL_CERT_DAYS_REMAINING
        )
        or freeradius_ok is False
    ):
        status = SiteStatus.critical
    elif (
        (crl_hours_remaining is not None and crl_hours_remaining <= site.crl_validity_days * 24 / 2)
        or (server_cert is not None and cert_service.renewal_due(server_cert, now))
        or missed_intervals > WARN_MISSED_INTERVALS
    ):
        status = SiteStatus.warn
    else:
        status = SiteStatus.ok

    return SiteHealth(
        site_id=site.id,
        name=site.name,
        radius_cn=site.radius_cn,
        subsidiary=site.subsidiary,
        status=status,
        last_seen_at=last_seen,
        minutes_since_checkin=minutes_since_checkin,
        crl_hours_remaining=crl_hours_remaining,
        crl_is_current=crl_freshness.is_current if crl_freshness else None,
        server_cert_days_remaining=server_cert_days_remaining,
        freeradius_ok=freeradius_ok,
        agent_version=site.agent_version,
    )


def evaluate_fleet(session: Session, now: datetime.datetime | None = None) -> list[SiteHealth]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    sites = session.scalars(select(db.Site).where(db.Site.is_active.is_(True))).all()
    freshness_by_site = {
        f.site_id: f for f in crl_health.per_host_crl_freshness(session, sites)
    }

    results = []
    for site in sites:
        cert = (
            session.get(db.Certificate, site.server_cert_id)
            if site.server_cert_id
            else None
        )
        results.append(evaluate_site(site, cert, freshness_by_site.get(site.id), now))
    return results
