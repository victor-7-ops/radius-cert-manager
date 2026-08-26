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
    device_type: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    device_mac: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    device_serial: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    subsidiary: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

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
    ("device_mac", "VARCHAR"),
    ("device_serial", "VARCHAR"),
    ("subsidiary", "VARCHAR"),
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


def audit(
    session: Session, actor: str, action: str, target: str, detail: str | None = None
) -> None:
    session.add(AuditLog(actor=actor, action=action, target=target, detail=detail))
