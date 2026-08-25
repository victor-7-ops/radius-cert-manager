"""Issue/suspend/unsuspend/revoke — the mutation layer over pki.py + db.py.

Handoff §5.3: every PKI mutation takes an exclusive flock so two
concurrent issuances can't race on the serial counter. The DB row is
written (and committed) before returning success — a cert that exists in
issued/ but not in SQLite is trusted but invisible to the UI and
unrevokable, the worst failure mode in the system. request_id dedupes a
timeout-and-retry so it never mints two certificates.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from filelock import FileLock
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db, pki


class CNConflictError(Exception):
    pass


@dataclass
class IssueResult:
    certificate: db.Certificate
    bundle: pki.Pkcs12Bundle | None
    deduped: bool = False


def _lock(pki_path: Path) -> FileLock:
    return FileLock(str(pki_path / ".pki.lock"), timeout=30)


def _unique_serial(session: Session) -> int:
    while True:
        serial = pki.generate_serial()
        exists = session.scalar(
            select(db.Certificate).where(db.Certificate.serial == str(serial))
        )
        if exists is None:
            return serial


def _issue_one_locked(
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    cn: str,
    note: str | None,
    request_id: str,
    export_password: str | None,
    issued_by: str,
    days: int,
    batch_id: str | None,
) -> IssueResult:
    """Caller must already hold _lock(pki_path)."""
    existing = session.scalar(select(db.Certificate).where(db.Certificate.request_id == request_id))
    if existing is not None:
        # Retried submission with the same request_id: dedupe, don't
        # re-mint. The original .p12 is gone (never persisted), so
        # the caller gets the existing DB row with a fresh bundle
        # only if it still has the private key in memory — callers
        # that hit this path are expected to treat it as "already
        # issued", not to re-deliver a bundle.
        return IssueResult(certificate=existing, bundle=None, deduped=True)

    active_conflict = session.scalar(
        select(db.Certificate).where(
            db.Certificate.cn == cn, db.Certificate.status == db.CertStatus.active
        )
    )
    if active_conflict is not None:
        raise CNConflictError(f"active certificate already exists for CN={cn}")

    key = pki.generate_private_key()
    csr = pki.build_csr(key, cn)
    serial = _unique_serial(session)
    cert = pki.sign_client_cert(csr, inter_cert, inter_key, serial, days)
    bundle = pki.build_pkcs12(cn, key, cert, [inter_cert], password=export_password)

    issued_dir = pki_path / "issued"
    issued_dir.mkdir(parents=True, exist_ok=True)
    (issued_dir / f"{cn}.crt").write_bytes(pki.cert_to_pem(cert))

    row = db.Certificate(
        cn=cn,
        serial=str(serial),
        issued_at=cert.not_valid_before_utc,
        expires_at=cert.not_valid_after_utc,
        status=db.CertStatus.active,
        issued_by=issued_by,
        request_id=request_id,
        note=note,
        batch_id=batch_id,
    )
    session.add(row)
    db.audit(session, actor=issued_by, action="issue", target=cn, detail=f"serial={serial}")
    session.commit()
    session.refresh(row)

    return IssueResult(certificate=row, bundle=bundle)


def issue_certificate(
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    cn: str,
    note: str | None,
    request_id: str,
    export_password: str | None,
    issued_by: str,
    days: int,
    batch_id: str | None = None,
) -> IssueResult:
    with _lock(pki_path):
        return _issue_one_locked(
            session, pki_path, inter_cert, inter_key, cn, note, request_id,
            export_password, issued_by, days, batch_id,
        )


def _set_status(
    session: Session,
    pki_path: Path,
    serial: str,
    new_status: db.CertStatus,
    reason: str | None,
    actor: str,
) -> db.Certificate:
    with _lock(pki_path):
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise KeyError(f"no certificate with serial={serial}")
        cert.status = new_status
        cert.reason = reason
        cert.status_changed_at = datetime.datetime.now(datetime.timezone.utc)
        cert.status_changed_by = actor
        db.audit(
            session,
            actor=actor,
            action=new_status.value,
            target=cert.cn,
            detail=reason,
        )
        session.commit()
        session.refresh(cert)
        return cert


def suspend(session: Session, pki_path: Path, serial: str, reason: str, actor: str):
    return _set_status(session, pki_path, serial, db.CertStatus.suspended, reason, actor)


def unsuspend(session: Session, pki_path: Path, serial: str, actor: str):
    return _set_status(session, pki_path, serial, db.CertStatus.active, None, actor)


def revoke(session: Session, pki_path: Path, serial: str, reason: str, actor: str):
    return _set_status(session, pki_path, serial, db.CertStatus.revoked, reason, actor)


def regenerate_crl(
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    validity_days: int,
) -> bytes:
    """Revoked AND suspended certs go on the CRL — suspension uses the
    real certificateHold semantics and must actually block auth while
    active (handoff §0 decision 2)."""
    with _lock(pki_path):
        rows = session.scalars(
            select(db.Certificate).where(
                db.Certificate.status.in_([db.CertStatus.revoked, db.CertStatus.suspended])
            )
        ).all()
        revoked_serials = [
            (int(r.serial), r.status_changed_at or datetime.datetime.now(datetime.timezone.utc))
            for r in rows
        ]
        crl = pki.build_crl(inter_cert, inter_key, revoked_serials, validity_days)
        pem = pki.crl_to_pem(crl)
        (pki_path / "crl.pem").write_bytes(pem)
        return pem
