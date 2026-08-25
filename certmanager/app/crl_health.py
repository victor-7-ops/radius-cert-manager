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

from app.db import Base, audit
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


def get_health(session: Session) -> CrlHealth:
    state = _get_or_create(session)
    next_update = _aware(state.next_update)
    now = _now()
    hours_remaining = None
    is_stale = False
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


def record_generation(session: Session, next_update: datetime.datetime) -> None:
    state = _get_or_create(session)
    state.last_generated_at = _now()
    state.next_update = next_update
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
) -> PushResult:
    """Retry push_fn() with backoff. On continued failure, write an audit
    row and fire alert_fn(detail) — loud failure, not a silent one
    (handoff §8.5). sleep_fn/delays are injectable so tests never
    actually sleep 15 minutes."""
    import time

    sleep_fn = sleep_fn or time.sleep
    delays = delays if delays is not None else DEFAULT_RETRY_DELAYS_SECONDS

    result = None
    for i, delay in enumerate(delays):
        if delay:
            sleep_fn(delay)
        result = push_fn()
        record_push_result(session, result.ok)
        if result.ok:
            return result
        logger.warning("CRL push attempt %d/%d failed: %s", i + 1, len(delays), result.detail)

    audit(session, actor="system", action="crl_push_failed", target="crl.pem", detail=result.detail)
    session.commit()
    if alert_fn is not None:
        alert_fn(f"CRL push failed after {len(delays)} attempts: {result.detail}")
    return result
