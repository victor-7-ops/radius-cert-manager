"""Bulk issue — handoff §6.5.

Preview before commit: classify every identifier as valid/duplicate/
malformed before anything is signed. Duplicates can be skipped or routed
through reissue, chosen per row (this build supports skip; reissue-in-
batch is left to the single-cert reissue flow). One export password for
the whole batch, shown once, never in the manifest. A partial failure
does not roll back successful rows.
"""

from __future__ import annotations

import csv
import io
import zipfile
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, db
from app.validation import CN_RE

MAX_BATCH_SIZE = 100


class BatchTooLargeError(Exception):
    pass


@dataclass
class PreviewRow:
    identifier: str
    classification: str  # "valid" | "duplicate" | "malformed"
    reason: str | None = None


def parse_identifiers(raw_text: str) -> list[str]:
    return [line.strip() for line in raw_text.splitlines() if line.strip()]


def parse_csv(data: bytes) -> list[str]:
    text = data.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    out = []
    for row in reader:
        if not row:
            continue
        cell = row[0].strip()
        if cell:
            out.append(cell)
    return out


def classify(session: Session, identifiers: list[str]) -> list[PreviewRow]:
    if len(identifiers) > MAX_BATCH_SIZE:
        raise BatchTooLargeError(f"batch of {len(identifiers)} exceeds cap of {MAX_BATCH_SIZE}")

    seen_in_batch: set[str] = set()
    rows: list[PreviewRow] = []
    for identifier in identifiers:
        if not CN_RE.match(identifier):
            rows.append(PreviewRow(identifier, "malformed", "invalid characters or length"))
            continue
        if identifier in seen_in_batch:
            rows.append(PreviewRow(identifier, "duplicate", "duplicated within this batch"))
            continue
        active = session.scalar(
            select(db.Certificate).where(
                db.Certificate.cn == identifier, db.Certificate.status == db.CertStatus.active
            )
        )
        if active is not None:
            rows.append(PreviewRow(identifier, "duplicate", "active certificate already exists"))
            continue
        seen_in_batch.add(identifier)
        rows.append(PreviewRow(identifier, "valid"))
    return rows


@dataclass
class BatchRowResult:
    cn: str
    ok: bool
    serial: str | None = None
    error: str | None = None


@dataclass
class BatchResult:
    batch_id: str
    rows: list[BatchRowResult] = field(default_factory=list)

    @property
    def succeeded(self) -> list[BatchRowResult]:
        return [r for r in self.rows if r.ok]

    @property
    def failed(self) -> list[BatchRowResult]:
        return [r for r in self.rows if not r.ok]


def issue_batch(
    session: Session,
    pki_path,
    inter_cert,
    inter_key,
    identifiers: list[str],
    batch_id: str,
    export_password: str,
    issued_by: str,
    days: int,
) -> tuple[BatchResult, bytes]:
    """Issue every identifier under one shared export password, one shared
    batch_id, one flock spanning the whole batch (handoff §6.5). A
    per-row failure is recorded and does not stop or roll back the rest.
    Returns (result, zip_bytes) — zip contains one .p12 per success plus
    manifest.csv (cn, serial, expires_at — never the password)."""
    result = BatchResult(batch_id=batch_id)
    zip_buf = io.BytesIO()
    manifest_rows = []

    with cert_service._lock(pki_path):
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for cn in identifiers:
                request_id = f"{batch_id}:{cn}"
                try:
                    issue_result = cert_service._issue_one_locked(
                        session, pki_path, inter_cert, inter_key,
                        cn=cn, note=None, request_id=request_id,
                        export_password=export_password, issued_by=issued_by,
                        days=days, batch_id=batch_id,
                    )
                except cert_service.CNConflictError as e:
                    result.rows.append(BatchRowResult(cn=cn, ok=False, error=str(e)))
                    continue
                except Exception as e:  # noqa: BLE001 - one bad row must not sink the batch
                    result.rows.append(BatchRowResult(cn=cn, ok=False, error=str(e)))
                    continue

                cert = issue_result.certificate
                result.rows.append(BatchRowResult(cn=cn, ok=True, serial=cert.serial))
                if issue_result.bundle is not None:
                    zf.writestr(f"{cn}.p12", issue_result.bundle.data)
                manifest_rows.append((cn, cert.serial, cert.expires_at.isoformat()))

            manifest_buf = io.StringIO()
            writer = csv.writer(manifest_buf)
            writer.writerow(["cn", "serial", "expires_at"])
            writer.writerows(manifest_rows)
            zf.writestr("manifest.csv", manifest_buf.getvalue())

    return result, zip_buf.getvalue()
