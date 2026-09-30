"""SQLAlchemy models and queries.

SQLite is a queryable index over the PKI, not the source of truth for
certificate material (handoff §5.2). "Expired" is computed at query time
from expires_at, never stored as a status.
"""

from __future__ import annotations

import datetime
import enum
import uuid

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    create_engine,
    select,
    text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


class Base(DeclarativeBase):
    pass


class CertStatus(str, enum.Enum):
    active = "active"
    suspended = "suspended"
    revoked = "revoked"


class AdminRole(str, enum.Enum):
    admin = "admin"
    super_admin = "super_admin"
    viewer = "viewer"
    # Read-only (HANDOFF-COMPLIANCE.md §3): can see the cert list, detail
    # pages, activity log and dashboard, same as `admin` — but every
    # mutating route, plus bundle download and export, rejects it with
    # 403 (auth.require_write). subsidiary_scope applies to it exactly
    # as it does to `admin`.


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    cn: Mapped[str] = mapped_column(String, index=True)
    serial: Mapped[str] = mapped_column(String, unique=True, index=True)
    issued_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[CertStatus] = mapped_column(
        Enum(CertStatus), default=CertStatus.active, index=True
    )
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
    status_changed_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    issued_by: Mapped[str] = mapped_column(String)
    status_changed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    supersedes_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("certificates.id"), nullable=True
    )
    request_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    note: Mapped[str | None] = mapped_column(String, nullable=True)
    batch_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    # Device/owner tracking, so a cert maps back to a real device and
    # person, not just an opaque CN — the CN is often a hostname, which
    # doesn't tell you who to call when a laptop goes missing.
    employee_name: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    employee_key: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # Normalized (casefold, collapsed whitespace) form of employee_name —
    # app.validation.normalize_employee_key() — derived on every write,
    # never entered directly (HANDOFF-LIFECYCLE.md §1.1). employee_name
    # is free text and the display value; this is what offboarding's
    # revoke-all groups on, so "Juan Dela Cruz" and "juan dela cruz"
    # don't silently split into two different employees.
    device_type: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    device_model: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    device_mac: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    device_serial: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    subsidiary: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    expiry_alert_sent_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Set once expiry_alerts has notified about this cert nearing
    # expiry, so re-checking (there's no scheduler — see
    # app/expiry_alerts.py) doesn't re-alert on it every time.

    cert_type: Mapped[str] = mapped_column(String, default="client", index=True)
    # "client" (device cert, the whole app until now) or "server" (a
    # site's FreeRADIUS server cert — infrastructure, not a device).
    # Excluded from client cert lists/counts/bulk ops by default; see
    # HANDOFF-FLEET.md §3.1.

    site_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    # Set for cert_type="server" — which site's RADIUS box this cert
    # belongs to. No FK constraint (SQLite + this project's hand-rolled
    # migrations don't enforce them elsewhere either); site.py validates
    # the relationship at the application layer instead.

    retired_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    # Set via POST /certs/{serial}/retire (HANDOFF-LIFECYCLE.md §2.2) —
    # "not renewing, device retired": leaves the renewal cohort without
    # pretending the device was re-enrolled. The reason is written to the
    # audit trail (db.audit), not stored here — it belongs there, not as
    # a second free-text field to keep in sync.

    minimised_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    # Set by scripts/retention.py (HANDOFF-COMPLIANCE.md §1) once the
    # personal fields below have been cleared. serial/cn/issued_at/
    # expires_at/status/subsidiary are kept — the CRL and audit trail
    # still need them, and they aren't personal data once the identifiers
    # are gone. Never set while the cert is active or still CRL-relevant.

    supersedes: Mapped["Certificate | None"] = relationship(
        remote_side=[id], back_populates="superseded_by", uselist=False
    )
    superseded_by: Mapped[list["Certificate"]] = relationship(
        back_populates="supersedes"
    )

    def is_expired(self, now: datetime.datetime | None = None) -> bool:
        now = now or _now()
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            # SQLite drops tzinfo on round-trip; treat naive values as UTC.
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        return expires_at < now


class Admin(Base):
    __tablename__ = "admins"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[AdminRole] = mapped_column(Enum(AdminRole))
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    must_change_password: Mapped[bool] = mapped_column(default=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    subsidiary_scope: Mapped[str | None] = mapped_column(String, nullable=True)
    # None/blank = unrestricted (sees every subsidiary, same as today).
    # Set = this admin can only see/manage certs for that one company —
    # scoping is a role, so a super_admin should generally stay
    # unscoped; the UI doesn't prevent scoping one, but it isn't the
    # intended use.


class AdminSession(Base):
    """One row per issued session cookie — lets an admin see (and end)
    their own active sessions individually, rather than the previous
    all-or-nothing token_version bump. token_version is still checked
    too (belt and suspenders): bump_token_version revokes every row here
    for that admin, so a deactivation/reset/force-logout still can't be
    outrun by a session row that somehow survives."""

    __tablename__ = "admin_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    admin_id: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Site(Base):
    """A remote FreeRADIUS site (HANDOFF-FLEET.md §4.1). Pulls the CRL and
    renews its own server cert via app/routes/site.py; never pushed to,
    never trusted with the admin session cookie."""

    __tablename__ = "sites"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, index=True)
    subsidiary: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    radius_cn: Mapped[str] = mapped_column(String, unique=True, index=True)
    address: Mapped[str | None] = mapped_column(String, nullable=True)
    auth_token_hash: Mapped[str] = mapped_column(String)
    crl_validity_days: Mapped[int] = mapped_column(Integer, default=30)
    checkin_interval_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    last_seen_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_reported_crl_sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    last_reported_freeradius_ok: Mapped[bool | None] = mapped_column(nullable=True)
    server_cert_id: Mapped[str | None] = mapped_column(String, nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )
    notes: Mapped[str | None] = mapped_column(String, nullable=True)

    last_alerted_status: Mapped[str | None] = mapped_column(String, nullable=True)
    # Edge-triggered dedup for app/fleet_watch.py (HANDOFF-FLEET.md §5.1
    # TRAP): a SILENT site must fire exactly one alert, not one per
    # scheduler run for as long as it stays SILENT. Set to the status
    # that was last alerted on; scripts/fleet_watch.py only alerts again
    # when the derived status changes.


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
    actor: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String, index=True)
    target: Mapped[str] = mapped_column(String)
    detail: Mapped[str | None] = mapped_column(String, nullable=True)

    subsidiary: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    site_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    minimised_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    # Set by scripts/retention.py once `detail` has been cleared under
    # audit_retention_days (HANDOFF-COMPLIANCE.md §1). `actor`, `action`,
    # `target`, `timestamp`, `subsidiary`, `site_id` are kept — they're
    # what the audit trail itself needs. The row recording a retention run
    # is never itself minimised by that same run.
    # HANDOFF-FLEET.md §8.3: populated on write where the calling code
    # already knows it (a cert's subsidiary, a site's id/subsidiary).
    # Rows written before this column existed are backfilled once at
    # startup — see backfill_audit_log_subsidiary() — by joining target
    # (a cert's CN for cert-related actions) back to certificates.subsidiary.
    # NULL stays NULL for actions with no subsidiary dimension at all
    # (admin management, global CRL push) or where the target CN no
    # longer matches any certificate (e.g. it was later overwritten by a
    # same-CN reissue chain with a different subsidiary — ambiguous,
    # left alone rather than guessed).


class MigrationFlag(Base):
    """One-shot migration markers (HANDOFF-COMPLIANCE.md §6) — a step that
    should run once ever, not on every boot, records its name here after
    it runs. To force a deliberate re-run, delete the row (or the whole
    table; init_db recreates it) and restart."""

    __tablename__ = "migration_flags"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    ran_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=_now)


def make_engine(db_path: str):
    return create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})


def make_session_factory(engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)


# (new_column_name, SQL type) — appended here as the schema grows,
# since this project has no migration framework. init_db() adds any
# missing column to an existing table on startup; it never removes or
# renames one, so it's safe to run against a live DB every boot.
_CERTIFICATE_COLUMN_MIGRATIONS = [
    ("employee_name", "VARCHAR"),
    ("device_type", "VARCHAR"),
    ("device_model", "VARCHAR"),
    ("device_mac", "VARCHAR"),
    ("device_serial", "VARCHAR"),
    ("subsidiary", "VARCHAR"),
    ("expiry_alert_sent_at", "DATETIME"),
    ("cert_type", "VARCHAR DEFAULT 'client'"),
    ("site_id", "VARCHAR"),
    ("minimised_at", "DATETIME"),
    ("employee_key", "VARCHAR"),
    ("retired_at", "DATETIME"),
]

DEVICE_TYPES = ["Laptop", "Phone", "Tablet", "Desktop", "Other"]

# Company/subsidiary a cert's device belongs to — free text is allowed
# too (issue_certificate doesn't validate against this list), this is
# just what the issue form and bulk CSV offer as quick picks.
SUBSIDIARIES = [
    "Lezzgo Boracay",
    "Lezzgo Cebu",
    "Topline Business Development Corporation",
    "Light Fuels Corporation",
    "Commercial Fuel Trade",
    "Bay Mall",
    "BMEAD",
    "Others",
]

# Fixed (not hashed) colorway per subsidiary, so the same company always
# reads the same color across the dashboard chart, list chips, and detail
# page — a hash-based color risks two companies landing on the same hue.
SUBSIDIARY_COLORS = {
    "Lezzgo Boracay": "#0ea5e9",
    "Lezzgo Cebu": "#06b6d4",
    "Topline Business Development Corporation": "#1e3a8a",
    "Light Fuels Corporation": "#f59e0b",
    "Commercial Fuel Trade": "#ea580c",
    "Bay Mall": "#8b5cf6",
    "BMEAD": "#ec4899",
    "Others": "#64748b",
}
SUBSIDIARY_COLOR_UNASSIGNED = "#cbd5e1"


def subsidiary_color(name: str | None) -> str:
    if not name:
        return SUBSIDIARY_COLOR_UNASSIGNED
    return SUBSIDIARY_COLORS.get(name, SUBSIDIARY_COLOR_UNASSIGNED)


_ADMIN_COLUMN_MIGRATIONS = [
    ("subsidiary_scope", "VARCHAR"),
]

_SITE_COLUMN_MIGRATIONS = [
    ("last_alerted_status", "VARCHAR"),
]

_AUDIT_LOG_COLUMN_MIGRATIONS = [
    ("subsidiary", "VARCHAR"),
    ("site_id", "VARCHAR"),
    ("minimised_at", "DATETIME"),
]


def _migrate_columns(engine, table: str, migrations: list[tuple[str, str]]) -> None:
    with engine.begin() as conn:
        existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
        if not existing:
            return  # table doesn't exist yet — create_all will make it with all columns
        for column_name, sql_type in migrations:
            if column_name not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column_name} {sql_type}"))


def init_db(engine) -> None:
    Base.metadata.create_all(engine)
    _migrate_columns(engine, "certificates", _CERTIFICATE_COLUMN_MIGRATIONS)
    _migrate_columns(engine, "admins", _ADMIN_COLUMN_MIGRATIONS)
    _migrate_columns(engine, "sites", _SITE_COLUMN_MIGRATIONS)
    _migrate_columns(engine, "audit_log", _AUDIT_LOG_COLUMN_MIGRATIONS)
    run_once(engine, "audit_log_subsidiary_backfill", lambda: backfill_audit_log_subsidiary(engine))
    run_once(engine, "certificate_employee_key_backfill", lambda: backfill_employee_key(engine))


def run_once(engine, name: str, fn) -> bool:
    """Runs fn() and records `name` as done, unless it already is. Used to
    guard a startup migration step that scans a table (like the audit-log
    subsidiary backfill below) behind a flag instead of re-scanning every
    boot forever (HANDOFF-COMPLIANCE.md §6). Returns True if fn() ran."""
    with Session(engine) as session:
        if session.get(MigrationFlag, name) is not None:
            return False
        fn()
        session.add(MigrationFlag(name=name))
        session.commit()
        return True


def backfill_audit_log_subsidiary(engine) -> int:
    """HANDOFF-FLEET.md §8.3: for rows written before AuditLog.subsidiary
    existed, derive it from the target certificate's CN where possible.
    Idempotent (only touches subsidiary IS NULL rows). init_db() runs this
    exactly once (via run_once/MigrationFlag, HANDOFF-COMPLIANCE.md §6)
    rather than scanning the whole audit_log table on every boot forever;
    call it directly (as this function, or via scripts/rerun_audit_backfill.py)
    to deliberately re-run it — e.g. after correcting a certificate's
    subsidiary that audit rows should now pick up.
    Returns the number of rows updated."""
    with Session(engine) as session:
        cn_to_subsidiary = dict(
            session.execute(
                select(Certificate.cn, Certificate.subsidiary).where(
                    Certificate.subsidiary.is_not(None)
                )
            ).all()
        )
        if not cn_to_subsidiary:
            return 0

        rows = session.scalars(
            select(AuditLog).where(AuditLog.subsidiary.is_(None))
        ).all()
        updated = 0
        for row in rows:
            subsidiary = cn_to_subsidiary.get(row.target)
            if subsidiary is not None:
                row.subsidiary = subsidiary
                updated += 1
        if updated:
            session.commit()
        return updated


def backfill_employee_key(engine) -> int:
    """HANDOFF-LIFECYCLE.md §1.1: for rows written before employee_key
    existed, derive it from employee_name. Idempotent (only touches
    employee_key IS NULL rows). init_db() runs this exactly once (via
    run_once/MigrationFlag); call it directly to deliberately re-run it
    after a bulk correction to employee_name. Returns the number of rows
    updated."""
    from app.validation import normalize_employee_key

    with Session(engine) as session:
        rows = session.scalars(
            select(Certificate).where(
                Certificate.employee_key.is_(None), Certificate.employee_name.is_not(None)
            )
        ).all()
        updated = 0
        for row in rows:
            key = normalize_employee_key(row.employee_name)
            if key is not None:
                row.employee_key = key
                updated += 1
        if updated:
            session.commit()
        return updated


def audit(
    session: Session,
    actor: str,
    action: str,
    target: str,
    detail: str | None = None,
    subsidiary: str | None = None,
    site_id: str | None = None,
) -> None:
    session.add(
        AuditLog(
            actor=actor, action=action, target=target, detail=detail,
            subsidiary=subsidiary, site_id=site_id,
        )
    )
