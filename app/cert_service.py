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
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from filelock import FileLock
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db, pki
from app.validation import normalize_employee_key


class CNConflictError(Exception):
    pass


class CSRCNMismatchError(Exception):
    """CSR's CN doesn't match the requesting site's registered CN — a site
    must never be able to obtain a certificate for another site
    (HANDOFF-FLEET.md §3.2)."""


@dataclass
class DeviceInfo:
    """Who and what a cert was issued for — tracking metadata only, never
    part of the cert itself. Defaults to all-None so existing call sites
    (and the reissue/imported paths that have no device info) don't need
    to change."""

    employee_name: str | None = None
    device_type: str | None = None
    device_model: str | None = None
    device_mac: str | None = None
    device_serial: str | None = None
    subsidiary: str | None = None


@dataclass
class NetworkAssignment:
    """Trusted authorization assignment built into the signed certificate (Schema 2).
    
    Signed attributes:
      O = subsidiary_id
      OU = network_role_id
    """

    subsidiary_id: str
    department_id: str
    network_role_id: str
    employee_id: str | None = None
    device_id: str | None = None


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
    device: DeviceInfo | None = None,
    supersedes_id: str | None = None,
    skip_conflict_check: bool = False,
    assignment: NetworkAssignment | None = None,
) -> IssueResult:
    """Caller must already hold _lock(pki_path)."""
    existing = session.scalar(select(db.Certificate).where(db.Certificate.request_id == request_id))
    if existing is not None:
        if assignment is not None:
            expected_fp = hashlib.sha256(
                f"{cn}:{assignment.subsidiary_id}:{assignment.department_id}:{assignment.network_role_id}:{assignment.device_id or ''}".encode()
            ).hexdigest()
            if existing.request_fingerprint and existing.request_fingerprint != expected_fp:
                raise ValueError("Reused request_id with differing assignment or CN")
            if existing.subsidiary_id and existing.subsidiary_id != assignment.subsidiary_id:
                raise ValueError("Reused request_id with differing subsidiary")
        return IssueResult(certificate=existing, bundle=None, deduped=True)

    if not skip_conflict_check:
        active_conflict = session.scalar(
            select(db.Certificate).where(
                db.Certificate.cn == cn,
                db.Certificate.status == db.CertStatus.active,
                db.Certificate.cert_type == "client",
            )
        )
        if active_conflict is not None:
            raise CNConflictError(f"active certificate already exists for CN={cn}")

    key = pki.generate_private_key()
    csr = pki.build_csr(key, cn)
    serial = _unique_serial(session)
    
    sub_id = assignment.subsidiary_id if assignment else None
    role_id = assignment.network_role_id if assignment else None
    cert = pki.sign_client_cert(
        csr, inter_cert, inter_key, serial, days,
        subsidiary_id=sub_id, network_role_id=role_id,
    )
    # The .p12 must carry the full CA chain, not just the intermediate --
    # a client validating the real RADIUS server's cert needs to build
    # trust all the way to the self-signed root, and Android in
    # particular has no separate mechanism to pick up a root that isn't
    # in the bundle itself (unlike Windows/Apple, which get the root
    # installed separately via the onboarding zip/.mobileconfig).
    # Confirmed live, 29 Oct 2026: with only the intermediate in the
    # bundle, Android's EAP-TLS setup had nothing valid to offer as a
    # distinct "CA certificate" and authentication never even reached
    # the RADIUS server. root.crt lives alongside intermediate.crt at
    # the top of pki_path (see app/main.py's own root_cert loading).
    root_path = pki_path / "root.crt"
    chain = [inter_cert]
    if root_path.exists():
        chain.append(pki.load_cert_pem(root_path))
    bundle = pki.build_pkcs12(cn, key, cert, chain, password=export_password)

    issued_dir = pki_path / "issued"
    issued_dir.mkdir(parents=True, exist_ok=True)
    # Serial in the filename, not just the CN — two certs can share a CN
    # over time (revoke-and-reissue, or an overlap-window reissue), and a
    # bare "{cn}.crt" name would silently overwrite the earlier file.
    (issued_dir / f"{cn}.{serial}.crt").write_bytes(pki.cert_to_pem(cert))

    device = device or DeviceInfo()
    schema_ver = 2 if assignment else 1
    snapshot_json = None
    req_fp = None
    if assignment:
        req_fp = hashlib.sha256(
            f"{cn}:{assignment.subsidiary_id}:{assignment.department_id}:{assignment.network_role_id}:{assignment.device_id or ''}".encode()
        ).hexdigest()
        snapshot_json = json.dumps({
            "subsidiary_id": assignment.subsidiary_id,
            "department_id": assignment.department_id,
            "network_role_id": assignment.network_role_id,
            "employee_id": assignment.employee_id,
            "device_id": assignment.device_id,
            "issued_by": issued_by,
            "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })

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
        employee_name=device.employee_name,
        employee_key=normalize_employee_key(device.employee_name),
        device_type=device.device_type,
        device_model=device.device_model,
        device_mac=device.device_mac,
        device_serial=device.device_serial,
        subsidiary=device.subsidiary,
        supersedes_id=supersedes_id,
        subsidiary_id=assignment.subsidiary_id if assignment else None,
        department_id=assignment.department_id if assignment else None,
        network_role_id=assignment.network_role_id if assignment else None,
        employee_id=assignment.employee_id if assignment else None,
        device_id=assignment.device_id if assignment else None,
        identity_schema_version=schema_ver,
        issuance_policy_snapshot=snapshot_json,
        request_fingerprint=req_fp,
    )
    session.add(row)
    audit_detail = f"serial={serial}"
    if device.employee_name:
        audit_detail += f" employee={device.employee_name}"
    if supersedes_id:
        audit_detail += f" supersedes={supersedes_id}"
    if assignment:
        audit_detail += f" role={assignment.network_role_id} dept={assignment.department_id}"
    db.audit(
        session, actor=issued_by, action="issue", target=cn, detail=audit_detail,
        subsidiary=device.subsidiary,
    )
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
    device: DeviceInfo | None = None,
    assignment: NetworkAssignment | None = None,
) -> IssueResult:
    with _lock(pki_path):
        return _issue_one_locked(
            session, pki_path, inter_cert, inter_key, cn, note, request_id,
            export_password, issued_by, days, batch_id, device,
            assignment=assignment,
        )


class ReissueTargetError(Exception):
    pass


def reissue_certificate(
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    old_serial: str,
    request_id: str,
    export_password: str | None,
    issued_by: str,
    days: int,
    assignment: NetworkAssignment | None = None,
) -> IssueResult:
    """Handoff §8.1: generate a new cert under the SAME CN as an existing
    one, linked via supersedes_id. Old and new coexist — the old cert is
    not touched here; suspending/revoking it is a separate, deliberate
    admin action once the new one is confirmed installed. Device/owner
    tracking metadata carries over from the old cert unchanged, since a
    reissue is "same device, new cert", not a new device."""
    with _lock(pki_path):
        old = session.scalar(select(db.Certificate).where(db.Certificate.serial == old_serial))
        if old is None:
            raise ReissueTargetError(f"no certificate with serial={old_serial}")
        if old.status == db.CertStatus.revoked:
            raise ReissueTargetError("cannot reissue a revoked certificate")

        device = DeviceInfo(
            employee_name=old.employee_name,
            device_type=old.device_type,
            device_model=old.device_model,
            device_mac=old.device_mac,
            device_serial=old.device_serial,
            subsidiary=old.subsidiary,
        )
        if assignment is None and old.subsidiary_id and old.network_role_id:
            assignment = NetworkAssignment(
                subsidiary_id=old.subsidiary_id,
                department_id=old.department_id,
                network_role_id=old.network_role_id,
                employee_id=old.employee_id,
                device_id=old.device_id,
            )

        return _issue_one_locked(
            session, pki_path, inter_cert, inter_key,
            cn=old.cn, note=old.note, request_id=request_id,
            export_password=export_password, issued_by=issued_by, days=days,
            batch_id=None, device=device, supersedes_id=old.id, skip_conflict_check=True,
            assignment=assignment,
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
            subsidiary=cert.subsidiary,
            site_id=cert.site_id,
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


def issue_server_cert(
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    csr_pem: bytes,
    site_id: str,
    site_cn: str,
    request_id: str,
    days: int,
    issued_by: str,
) -> IssueResult:
    """Sign a RADIUS server cert from a site-supplied CSR (HANDOFF-FLEET.md
    §3.2). The private key never travels: the site generates it and sends
    only the CSR. The CSR's CN must match the site's own registered CN, or
    one site could obtain a cert for another site's identity."""
    csr = x509.load_pem_x509_csr(csr_pem)
    csr_cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if csr_cn != site_cn:
        raise CSRCNMismatchError(f"CSR CN {csr_cn!r} does not match site CN {site_cn!r}")

    with _lock(pki_path):
        existing = session.scalar(
            select(db.Certificate).where(db.Certificate.request_id == request_id)
        )
        if existing is not None:
            return IssueResult(certificate=existing, bundle=None, deduped=True)

        serial = _unique_serial(session)
        cert = pki.sign_server_cert(csr, inter_cert, inter_key, serial, days)

        issued_dir = pki_path / "issued"
        issued_dir.mkdir(parents=True, exist_ok=True)
        (issued_dir / f"{site_cn}.{serial}.crt").write_bytes(pki.cert_to_pem(cert))

        row = db.Certificate(
            cn=site_cn,
            serial=str(serial),
            issued_at=cert.not_valid_before_utc,
            expires_at=cert.not_valid_after_utc,
            status=db.CertStatus.active,
            issued_by=issued_by,
            request_id=request_id,
            cert_type="server",
            site_id=site_id,
        )
        session.add(row)
        db.audit(
            session, actor=issued_by, action="issue_server_cert", target=site_cn,
            detail=f"serial={serial} site_id={site_id}",
            site_id=site_id,
        )
        session.commit()
        session.refresh(row)

        return IssueResult(certificate=row, bundle=None)


def renewal_due(cert: db.Certificate, now: datetime.datetime | None = None, offset_days: int = 0) -> bool:
    """True when less than one third of the cert's lifetime remains
    (HANDOFF-FLEET.md §3.3) — renewal is due early, not at the last
    minute. offset_days shifts the threshold later by a site's
    renewal_offset() so a fleet onboarded on the same day doesn't all
    become due on the same night."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    issued_at = cert.issued_at
    expires_at = cert.expires_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=datetime.timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    lifetime = expires_at - issued_at
    renew_at = issued_at + (lifetime * 2 / 3) + datetime.timedelta(days=offset_days)
    return now >= renew_at


def renewal_offset(site_id: str, window_days: int) -> int:
    """Deterministic per-site offset (in days, [0, window_days)) so a
    fleet of sites doesn't renew on the same night (HANDOFF-FLEET.md
    §3.3) — a bad automated renewal breaks one site, not all of them."""
    if window_days <= 0:
        return 0
    digest = hashlib.sha256(site_id.encode()).hexdigest()
    return int(digest, 16) % window_days


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
        revoked_serials = []
        for r in rows:
            rev_date = r.status_changed_at or datetime.datetime.now(datetime.timezone.utc)
            if r.status == db.CertStatus.suspended:
                reason = x509.ReasonFlags.certificate_hold
            else:
                reason = (
                    x509.ReasonFlags.key_compromise
                    if r.reason and "compromise" in r.reason.lower()
                    else x509.ReasonFlags.unspecified
                )
            revoked_serials.append((int(r.serial), rev_date, reason))
        crl = pki.build_crl(inter_cert, inter_key, revoked_serials, validity_days)
        pem = pki.crl_to_pem(crl)
        (pki_path / "crl.pem").write_bytes(pem)
        return pem
