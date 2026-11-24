"""CRL freshness tracking + push retry/alerting.

Handoff §8.3: this is the highest-risk operational item in the system —
an expired CRL fails closed and takes down all EAP-TLS auth. §8.5: push
failure must be loud, not silent. Retry with backoff (3 attempts over 15
minutes), then write an audit_log entry and surface the alert.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass

from sqlalchemy import DateTime, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db import Base, Site, audit
from app.crl_push import PushResult

logger = logging.getLogger("certmanager.crl_health")

DEFAULT_RETRY_DELAYS_SECONDS = [0, 300, 600]  # 3 attempts over 15 minutes total
CRITICAL_HOURS_REMAINING = 48


class CrlState(Base):
    """Single-row table: current CRL freshness state."""

    __tablename__ = "crl_state"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: "singleton")
    last_generated_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_pushed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_push_ok: Mapped[bool | None] = mapped_column(nullable=True)
    next_update: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The hub's own current CRL file hash (handoff task N item 2) --
    # compared against each Site.last_reported_crl_sha256 to tell
    # whether that site is actually running the latest CRL, not just
    # whether the hub's own copy is fresh. The two questions are
    # different: the hub can have a brand-new CRL while a site that
    # missed a checkin is still running a week-old one.
    current_sha256: Mapped[str | None] = mapped_column(String, nullable=True)


def _get_or_create(session: Session) -> CrlState:
    state = session.get(CrlState, "singleton")
    if state is None:
        state = CrlState(id="singleton")
        session.add(state)
        session.commit()
    return state


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime | None) -> datetime.datetime | None:
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=datetime.timezone.utc)


@dataclass
class CrlHealth:
    last_generated_at: datetime.datetime | None
    last_pushed_at: datetime.datetime | None
    last_push_ok: bool | None
    next_update: datetime.datetime | None
    hours_remaining: float | None
    is_critical: bool
    is_stale: bool


def banner_context(session: Session) -> dict:
    """Template context for the site-wide stale-CRL banner (handoff §6.3)
    — every authenticated page includes this."""
    return {"crl_critical": get_health(session).is_critical}


def get_health(session: Session) -> CrlHealth:
    state = _get_or_create(session)
    next_update = _aware(state.next_update)
    now = _now()
    hours_remaining = None
    is_stale = next_update is None
    if next_update is not None:
        delta = next_update - now
        hours_remaining = delta.total_seconds() / 3600
        is_stale = hours_remaining <= 0
    is_critical = (
        is_stale
        or state.last_push_ok is False
        or (hours_remaining is not None and hours_remaining < CRITICAL_HOURS_REMAINING)
    )
    return CrlHealth(
        last_generated_at=_aware(state.last_generated_at),
        last_pushed_at=_aware(state.last_pushed_at),
        last_push_ok=state.last_push_ok,
        next_update=next_update,
        hours_remaining=hours_remaining,
        is_critical=is_critical,
        is_stale=is_stale,
    )


@dataclass
class HostCrlFreshness:
    site_id: str
    name: str
    radius_cn: str
    reported_sha256: str | None
    is_current: bool
    hours_remaining: float | None
    is_critical: bool


def per_host_crl_freshness(session: Session, sites: list[Site] | None = None) -> list[HostCrlFreshness]:
    """Per-site CRL freshness (handoff task N item 2 -- round 2's Task 2
    asked for this and it never landed; the multi-host push exists, the
    multi-host monitoring did not). Reuses get_health()'s fleet-wide
    hours_remaining/is_critical logic for a site that IS running the
    current CRL; a site running anything else (stale, or no checkin yet)
    is reported critical outright, since the hub has no record of when
    that older CRL it's still running actually expires."""
    health = get_health(session)
    state = _get_or_create(session)
    sites = sites if sites is not None else session.scalars(select(Site).where(Site.is_active.is_(True))).all()

    results = []
    for site in sites:
        reported = site.last_reported_crl_sha256
        # No reported hash yet (fresh install, never checked in) must
        # read critical, not "fine because we don't know" -- same bug
        # shape as get_health's own fresh-install fix (18 Nov 2026).
        is_current = reported is not None and state.current_sha256 is not None and reported == state.current_sha256
        if is_current:
            results.append(HostCrlFreshness(
                site_id=site.id, name=site.name, radius_cn=site.radius_cn,
                reported_sha256=reported, is_current=True,
                hours_remaining=health.hours_remaining, is_critical=health.is_critical,
            ))
        else:
            results.append(HostCrlFreshness(
                site_id=site.id, name=site.name, radius_cn=site.radius_cn,
                reported_sha256=reported, is_current=False,
                hours_remaining=None, is_critical=True,
            ))
    return results


def record_generation(session: Session, next_update: datetime.datetime, sha256: str | None = None) -> None:
    state = _get_or_create(session)
    state.last_generated_at = _now()
    state.next_update = next_update
    if sha256 is not None:
        state.current_sha256 = sha256
    session.commit()


def record_push_result(session: Session, ok: bool) -> None:
    state = _get_or_create(session)
    state.last_pushed_at = _now()
    state.last_push_ok = ok
    session.commit()


def push_with_retry(
    session: Session,
    push_fn: callable,
    alert_fn: callable | None,
    sleep_fn: callable = None,
    delays: list[int] = None,
    host: str | None = None,
) -> PushResult:
    """Retry push_fn() with backoff. On continued failure, write an audit
    row and fire alert_fn(detail) — loud failure, not a silent one
    (handoff §8.5). sleep_fn/delays are injectable so tests never
    actually sleep 15 minutes. `host` is cosmetic only (audit/alert
    detail) — multiple hosts share crl_state, so last_push_ok reflects
    whichever host pushed most recently."""
    import time

    sleep_fn = sleep_fn or time.sleep
    delays = delays if delays is not None else DEFAULT_RETRY_DELAYS_SECONDS
    host_label = f"{host}: " if host else ""

    result = None
    for i, delay in enumerate(delays):
        if delay:
            sleep_fn(delay)
        result = push_fn()
        record_push_result(session, result.ok)
        if result.ok:
            return result
        logger.warning(
            "CRL push attempt %d/%d failed (%s): %s", i + 1, len(delays), host or "?", result.detail
        )

    audit(
        session,
        actor="system",
        action="crl_push_failed",
        target="crl.pem",
        detail=f"{host_label}{result.detail}",
    )
    session.commit()
    if alert_fn is not None:
        alert_fn(f"CRL push failed after {len(delays)} attempts ({host_label}{result.detail})")
    return result
