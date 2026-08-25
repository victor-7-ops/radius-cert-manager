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


def init_db(engine) -> None:
    Base.metadata.create_all(engine)


def audit(
    session: Session, actor: str, action: str, target: str, detail: str | None = None
) -> None:
    session.add(AuditLog(actor=actor, action=action, target=target, detail=detail))
