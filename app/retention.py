"""Retention and data minimisation (HANDOFF-COMPLIANCE.md §1).

There is no deletion or minimisation logic anywhere else in this codebase —
certificates, audit rows, and admin sessions accumulate permanently unless
this module is run. Everything here is opt-in: every *_retention_days
setting defaults to None, and None means "do nothing" (handoff: only the
DPO sets these — this app must never guess a value).

Certificates are ANONYMISED, never deleted: a revoked certificate's serial
must stay queryable (CRL history, audit trail) for as long as it's
CRL-relevant, so deleting the row would be a security regression dressed
as a privacy improvement. Only the personal fields are cleared.

Admin sessions are deleted outright — nothing downstream depends on them.

Audit rows are anonymised (their `detail` cleared), never deleted, and on
a *separate* retention period from certificates: audit and enrolment
retention answer to different obligations.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db
from app.config import Settings

# Bounds each category's work per run so a first pass against a large,
# never-before-run table can't hang the box or hold one long transaction.
# A run that hits the cap is still correct — it just leaves the rest for
# the next scheduled invocation.
BATCH_SIZE = 500


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


@dataclass
class RetentionReport:
    """What a run would do (dry-run) or did do (applied) — same shape
    either way, so the health page and the DPO-facing dry-run output share
    one code path."""

    certs_eligible: list[db.Certificate] = field(default_factory=list)
    audit_rows_eligible: list[db.AuditLog] = field(default_factory=list)
    sessions_eligible: list[db.AdminSession] = field(default_factory=list)
    applied: bool = False

    @property
    def cert_count(self) -> int:
        return len(self.certs_eligible)

    @property
    def audit_count(self) -> int:
        return len(self.audit_rows_eligible)

    @property
    def session_count(self) -> int:
        return len(self.sessions_eligible)


def _cert_cutoff_reached(cert: db.Certificate, retention_days: int, now: datetime.datetime) -> bool:
    """A cert is only eligible once it is BOTH expired and revoked, and
    retention_days have passed since the later of the two — an unexpired
    revoked cert must keep its serial on the CRL (handoff §1.1), and an
    expired-but-still-active cert is a live credential, not a retired one."""
    if cert.status != db.CertStatus.revoked:
        return False
    if not cert.is_expired(now):
        return False
    reference = _aware(cert.status_changed_at or cert.expires_at)
    expires_at = _aware(cert.expires_at)
    anchor = max(reference, expires_at)
    return now >= anchor + datetime.timedelta(days=retention_days)


def find_eligible_certs(session: Session, retention_days: int, now: datetime.datetime | None = None) -> list[db.Certificate]:
    now = now or _now()
    candidates = session.scalars(
        select(db.Certificate).where(
            db.Certificate.cert_type == "client",
            db.Certificate.minimised_at.is_(None),
            db.Certificate.status == db.CertStatus.revoked,
        ).limit(BATCH_SIZE * 4)  # generous prefilter; is_expired/cutoff check is in Python
    ).all()
    eligible = [c for c in candidates if _cert_cutoff_reached(c, retention_days, now)]
    return eligible[:BATCH_SIZE]


def find_eligible_audit_rows(session: Session, retention_days: int, now: datetime.datetime | None = None) -> list[db.AuditLog]:
    now = now or _now()
    cutoff = now - datetime.timedelta(days=retention_days)
    rows = session.scalars(
        select(db.AuditLog)
        .where(db.AuditLog.minimised_at.is_(None), db.AuditLog.timestamp <= cutoff)
        .limit(BATCH_SIZE)
    ).all()
    return list(rows)


def find_eligible_sessions(session: Session, retention_days: int, now: datetime.datetime | None = None) -> list[db.AdminSession]:
    now = now or _now()
    cutoff = now - datetime.timedelta(days=retention_days)
    rows = session.scalars(
        select(db.AdminSession).where(db.AdminSession.last_seen_at <= cutoff).limit(BATCH_SIZE)
    ).all()
    return list(rows)


def build_report(session: Session, settings: Settings, now: datetime.datetime | None = None) -> RetentionReport:
    """Read-only: what run_retention() would touch. Unset config means
    that category contributes nothing — this is what dry-run mode shows
    the DPO, and what /health surfaces as eligibility counts."""
    now = now or _now()
    return RetentionReport(
        certs_eligible=(
            find_eligible_certs(session, settings.cert_retention_days, now)
            if settings.cert_retention_days is not None
            else []
        ),
        audit_rows_eligible=(
            find_eligible_audit_rows(session, settings.audit_retention_days, now)
            if settings.audit_retention_days is not None
            else []
        ),
        sessions_eligible=(
            find_eligible_sessions(session, settings.session_retention_days, now)
            if settings.session_retention_days is not None
            else []
        ),
    )


def run_retention(session: Session, settings: Settings, dry_run: bool = True, now: datetime.datetime | None = None) -> RetentionReport:
    """Dry-run by default — callers must opt into dry_run=False to mutate
    anything. Every category that actually changes something writes its
    own audit_log row recording what and under which policy; that row is
    written and committed in a step separate from (and after) the mutating
    commit, so it can never be swept up by the same run."""
    now = now or _now()
    report = build_report(session, settings, now)
    if dry_run:
        return report

    if report.certs_eligible:
        for cert in report.certs_eligible:
            cert.employee_name = None
            cert.device_mac = None
            cert.device_serial = None
            cert.device_model = None
            cert.minimised_at = now
        session.commit()
        db.audit(
            session,
            actor="system",
            action="retention.certs_minimised",
            target="certificates",
            detail=f"{len(report.certs_eligible)} certificate(s) minimised "
            f"under cert_retention_days={settings.cert_retention_days}",
        )
        session.commit()

    if report.audit_rows_eligible:
        for row in report.audit_rows_eligible:
            row.detail = None
            row.minimised_at = now
        session.commit()
        db.audit(
            session,
            actor="system",
            action="retention.audit_minimised",
            target="audit_log",
            detail=f"{len(report.audit_rows_eligible)} audit row(s) minimised "
            f"under audit_retention_days={settings.audit_retention_days}",
        )
        session.commit()

    if report.sessions_eligible:
        count = len(report.sessions_eligible)
        for row in report.sessions_eligible:
            session.delete(row)
        session.commit()
        db.audit(
            session,
            actor="system",
            action="retention.sessions_deleted",
            target="admin_sessions",
            detail=f"{count} admin session(s) deleted "
            f"under session_retention_days={settings.session_retention_days}",
        )
        session.commit()

    report.applied = True
    return report
