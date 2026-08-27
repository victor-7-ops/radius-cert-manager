"""First-run import of pre-existing certs, and issued/-vs-DB reconciliation.

Handoff §5.8: on first run, scan pki/issued/, parse each cert, import CN,
serial, issue date, expiry into SQLite with issued_by="imported". The
§5.3 reconciliation must run *after* import, so pre-existing certs are
recorded rather than flagged as anomalies.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db, pki


def import_existing_certs(session: Session, issued_dir: Path) -> list[str]:
    imported: list[str] = []
    for cert_path in sorted(issued_dir.glob("*.crt")):
        cert = pki.load_cert_pem(cert_path)
        serial = str(cert.serial_number)
        existing = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if existing is not None:
            continue
        cn = cert.subject.get_attributes_for_oid(
            __import__("cryptography.x509.oid", fromlist=["NameOID"]).NameOID.COMMON_NAME
        )[0].value
        row = db.Certificate(
            cn=cn,
            serial=serial,
            issued_at=cert.not_valid_before_utc,
            expires_at=cert.not_valid_after_utc,
            status=db.CertStatus.active,
            issued_by="imported",
            request_id=f"imported-{serial}",
        )
        session.add(row)
        imported.append(cn)
    session.commit()
    return imported


def reconcile_issued_dir(session: Session, issued_dir: Path) -> list[str]:
    """Flag any .crt in issued/ that has no matching DB row. Run after import."""
    orphans: list[str] = []
    for cert_path in sorted(issued_dir.glob("*.crt")):
        cert = pki.load_cert_pem(cert_path)
        serial = str(cert.serial_number)
        existing = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if existing is None:
            orphans.append(cert_path.name)
    return orphans
