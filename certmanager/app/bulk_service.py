"""Bulk issue — handoff §6.5.

Preview before commit: classify every identifier as valid/duplicate/
malformed before anything is signed. Duplicates can be skipped or routed
through reissue, chosen per row (this build supports skip; reissue-in-
batch is left to the single-cert reissue flow). One export password for
the whole batch, shown once, never in the manifest. A partial failure
does not roll back successful rows.

Each row optionally carries employee_name/device_type/device_mac/
device_serial/subsidiary — paste input is identifier-only, CSV input may
add up to five more columns in that order. Either way it's optional per
row.
"""

from __future__ import annotations

import csv
import io
import zipfile
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, db
from app.validation import CN_RE, normalize_mac

MAX_BATCH_SIZE = 100
_CSV_HEADER_HINTS = {"cn", "identifier", "hostname"}


class BatchTooLargeError(Exception):
    pass


@dataclass
class BatchInputRow:
    identifier: str
    employee_name: str | None = None
    device_type: str | None = None
    device_mac: str | None = None
    device_serial: str | None = None
    subsidiary: str | None = None


@dataclass
class PreviewRow:
    identifier: str
    classification: str  # "valid" | "duplicate" | "malformed"
    reason: str | None = None
    employee_name: str | None = None
    device_type: str | None = None
    device_mac: str | None = None
    device_serial: str | None = None
    subsidiary: str | None = None


def parse_identifiers(raw_text: str) -> list[BatchInputRow]:
    return [BatchInputRow(identifier=line.strip()) for line in raw_text.splitlines() if line.strip()]


def parse_csv(data: bytes) -> list[BatchInputRow]:
    """Columns, in order: identifier, employee_name, device_type,
    device_mac, device_serial, subsidiary. Only the first is required. A
    header row is detected and skipped if its first cell looks like one."""
    text = data.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if r]
    if rows and rows[0] and rows[0][0].strip().lower() in _CSV_HEADER_HINTS:
        rows = rows[1:]

    out = []
    for row in rows:
        identifier = row[0].strip() if row else ""
        if not identifier:
            continue
        cells = [c.strip() or None for c in row[1:6]]
        cells += [None] * (5 - len(cells))
        employee_name, device_type, device_mac, device_serial, subsidiary = cells
        if device_mac:
            device_mac = normalize_mac(device_mac) or device_mac
        out.append(
            BatchInputRow(
                identifier=identifier,
                employee_name=employee_name,
                device_type=device_type,
                device_mac=device_mac,
                device_serial=device_serial,
                subsidiary=subsidiary,
            )
        )
    return out


def classify(session: Session, input_rows: list[BatchInputRow]) -> list[PreviewRow]:
    if len(input_rows) > MAX_BATCH_SIZE:
        raise BatchTooLargeError(f"batch of {len(input_rows)} exceeds cap of {MAX_BATCH_SIZE}")

    seen_in_batch: set[str] = set()
    rows: list[PreviewRow] = []
    for r in input_rows:
        common = {
            "employee_name": r.employee_name,
            "device_type": r.device_type,
            "device_mac": r.device_mac,
            "device_serial": r.device_serial,
            "subsidiary": r.subsidiary,
        }
        if not CN_RE.match(r.identifier):
            rows.append(PreviewRow(r.identifier, "malformed", "invalid characters or length", **common))
            continue
        if r.identifier in seen_in_batch:
            rows.append(PreviewRow(r.identifier, "duplicate", "duplicated within this batch", **common))
            continue
        active = session.scalar(
            select(db.Certificate).where(
                db.Certificate.cn == r.identifier, db.Certificate.status == db.CertStatus.active
            )
        )
        if active is not None:
            rows.append(PreviewRow(r.identifier, "duplicate", "active certificate already exists", **common))
            continue
        seen_in_batch.add(r.identifier)
        rows.append(PreviewRow(r.identifier, "valid", **common))
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
    input_rows: list[BatchInputRow],
    batch_id: str,
    export_password: str,
    issued_by: str,
    days: int,
) -> tuple[BatchResult, bytes]:
    """Issue every row under one shared export password, one shared
    batch_id, one flock spanning the whole batch (handoff §6.5). A
    per-row failure is recorded and does not stop or roll back the rest.
    Returns (result, zip_bytes) — zip contains one .p12 per success plus
    manifest.csv (cn, serial, expires_at, employee, device type, MAC,
    device serial — never the password)."""
    result = BatchResult(batch_id=batch_id)
    zip_buf = io.BytesIO()
    manifest_rows = []

    with cert_service._lock(pki_path):
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for r in input_rows:
                cn = r.identifier
                request_id = f"{batch_id}:{cn}"
                device = cert_service.DeviceInfo(
                    employee_name=r.employee_name,
                    device_type=r.device_type,
                    device_mac=r.device_mac,
                    device_serial=r.device_serial,
                    subsidiary=r.subsidiary,
                )
                try:
                    issue_result = cert_service._issue_one_locked(
                        session, pki_path, inter_cert, inter_key,
                        cn=cn, note=None, request_id=request_id,
                        export_password=export_password, issued_by=issued_by,
                        days=days, batch_id=batch_id, device=device,
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
                manifest_rows.append((
                    cn,
                    cert.serial,
                    cert.expires_at.isoformat(),
                    r.employee_name or "",
                    r.device_type or "",
                    r.device_mac or "",
                    r.device_serial or "",
                    r.subsidiary or "",
                ))

            manifest_buf = io.StringIO()
            writer = csv.writer(manifest_buf)
            writer.writerow(["cn", "serial", "expires_at", "employee_name", "device_type", "device_mac", "device_serial", "subsidiary"])
            writer.writerows(manifest_rows)
            zf.writestr("manifest.csv", manifest_buf.getvalue())

    return result, zip_buf.getvalue()
