"""Bulk issue — handoff §6.5.

Preview before commit: classify every identifier as valid/duplicate/
malformed before anything is signed. One export password for the whole
batch, shown once, never in the manifest. A partial failure does not
roll back successful rows.

renew_batch (below) is the bulk counterpart to a single reissue — pick
a selection of certs from the cert list (e.g. everything expiring
soon) and reissue all of them under one shared export password, same
partial-failure-doesn't-roll-back-the-rest rule.

Each row optionally carries employee_name/device_type/device_mac/
device_serial/subsidiary/device_model — paste input is identifier-only,
CSV input may add up to six more columns in that order (device_model
is appended last rather than inserted, so a CSV built against the
older 6-column order still parses unchanged). Either way it's optional
per row.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, db
from app.validation import CN_RE, normalize_mac

MAX_BATCH_SIZE = 100
_CSV_HEADER_HINTS = {"cn", "identifier", "hostname"}

# Header-name aliases for the by-name CSV path (see parse_csv). Keys are
# lowercased/stripped header text as it might realistically show up in
# an inventory export someone already has — not just the app's own
# template — mapped to the BatchInputRow field it fills. A column whose
# header matches nothing here (e.g. "Model") is ignored rather than
# rejected, so an extra column doesn't break the import.
_HEADER_ALIASES = {
    "identifier": {"cn", "identifier", "hostname"},
    "employee_name": {"employee_name", "employee", "name", "owner", "full name", "employee name"},
    "device_type": {"device_type", "device type", "type"},
    "device_model": {"device_model", "device model", "model", "brand", "brand/model", "brand and model", "make/model"},
    "device_mac": {"device_mac", "mac", "mac address", "device mac address", "device mac"},
    "device_serial": {"device_serial", "serial", "serial number", "asset tag", "device serial"},
    "subsidiary": {"subsidiary", "company", "company / subsidiary", "company/subsidiary"},
}


def _slugify_cn(*parts: str | None) -> str:
    """Turn free-text (a person's name, a serial number) into something
    that passes CN_RE — used when a by-name CSV has no identifier/cn/
    hostname column of its own to use as the certificate CN."""
    raw = "-".join(p for p in parts if p).lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:63] or "device"


class BatchTooLargeError(Exception):
    pass


@dataclass
class BatchInputRow:
    identifier: str
    employee_name: str | None = None
    device_type: str | None = None
    device_model: str | None = None
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
    device_model: str | None = None
    device_mac: str | None = None
    device_serial: str | None = None
    subsidiary: str | None = None


def parse_identifiers(raw_text: str) -> list[BatchInputRow]:
    return [BatchInputRow(identifier=line.strip()) for line in raw_text.splitlines() if line.strip()]


def _match_header_field(cell: str) -> str | None:
    cell = cell.strip().lower()
    for field_name, aliases in _HEADER_ALIASES.items():
        if cell in aliases:
            return field_name
    return None


def parse_csv(data: bytes) -> list[BatchInputRow]:
    """Two supported shapes:

    1. By-name header: the first row's cells are matched against
       _HEADER_ALIASES in any order, any subset, plus any number of
       unrecognized columns (ignored) — so a CSV exported from wherever
       device inventory already lives doesn't need reshuffling to match
       this app's column order. If no column matches identifier/cn/
       hostname, the CN is generated from employee_name + device_serial
       (or whatever's available) instead of left missing.

    2. Positional (no recognized header): identifier, employee_name,
       device_type, device_mac, device_serial, subsidiary, in that
       order — only the first is required. This is what the app's own
       "download a starter CSV" produces, and how a plain identifier-
       per-line paste has always been read as a 1-column CSV.
    """
    text = data.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text))
    rows = [r for r in reader if r]
    if not rows:
        return []

    header_map = {i: _match_header_field(cell) for i, cell in enumerate(rows[0])}
    has_named_header = any(header_map.values())

    if has_named_header:
        rows = rows[1:]
        has_identifier_column = "identifier" in header_map.values()
        out = []
        for row in rows:
            values = {}
            for i, cell in enumerate(row):
                field_name = header_map.get(i)
                if field_name:
                    values[field_name] = cell.strip() or None
            if values.get("device_mac"):
                values["device_mac"] = normalize_mac(values["device_mac"]) or values["device_mac"]
            if not any(values.values()):
                continue  # a blank row (e.g. a trailing CSV line with only an unmapped column set)
            identifier = values.get("identifier")
            if not identifier and not has_identifier_column:
                identifier = _slugify_cn(
                    values.get("employee_name"), values.get("device_type"), values.get("device_serial")
                )
            if not identifier:
                continue
            out.append(BatchInputRow(
                identifier=identifier,
                employee_name=values.get("employee_name"),
                device_type=values.get("device_type"),
                device_model=values.get("device_model"),
                device_mac=values.get("device_mac"),
                device_serial=values.get("device_serial"),
                subsidiary=values.get("subsidiary"),
            ))
        return out

    if rows[0] and rows[0][0].strip().lower() in _CSV_HEADER_HINTS:
        rows = rows[1:]

    out = []
    for row in rows:
        identifier = row[0].strip() if row else ""
        if not identifier:
            continue
        cells = [c.strip() or None for c in row[1:6]]
        cells += [None] * (5 - len(cells))
        employee_name, device_type, device_mac, device_serial, subsidiary = cells
        # device_model is appended as an optional 7th column rather than
        # inserted among the other five, so a CSV built against the old
        # 6-column positional order still parses unchanged.
        device_model = row[6].strip() or None if len(row) > 6 else None
        if device_mac:
            device_mac = normalize_mac(device_mac) or device_mac
        out.append(
            BatchInputRow(
                identifier=identifier,
                employee_name=employee_name,
                device_type=device_type,
                device_model=device_model,
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
            "device_model": r.device_model,
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
                db.Certificate.cn == r.identifier,
                db.Certificate.status == db.CertStatus.active,
                db.Certificate.cert_type == "client",
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
                    device_model=r.device_model,
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
                    r.device_model or "",
                    r.device_mac or "",
                    r.device_serial or "",
                    r.subsidiary or "",
                ))

            manifest_buf = io.StringIO()
            writer = csv.writer(manifest_buf)
            writer.writerow(["cn", "serial", "expires_at", "employee_name", "device_type", "device_model", "device_mac", "device_serial", "subsidiary"])
            writer.writerows(manifest_rows)
            zf.writestr("manifest.csv", manifest_buf.getvalue())

    return result, zip_buf.getvalue()


def renew_batch(
    session: Session,
    pki_path,
    inter_cert,
    inter_key,
    old_serials: list[str],
    batch_id: str,
    export_password: str,
    issued_by: str,
    days: int,
) -> tuple[BatchResult, bytes]:
    """Bulk version of cert_service.reissue_certificate — same-CN
    reissue for a whole selection of certs at once (typically "these
    are all expiring soon"), rather than one at a time from each cert's
    detail page. Same coexistence rule as a single reissue: the old
    cert is never touched here, only the new one is created linked via
    supersedes_id — suspending/revoking the old one is still a separate,
    deliberate action. Device/owner metadata carries over from each old
    cert unchanged. Returns the same (BatchResult, zip_bytes) shape as
    issue_batch so bulk_result.html can render either without knowing
    which one produced it."""
    result = BatchResult(batch_id=batch_id)
    zip_buf = io.BytesIO()
    manifest_rows = []

    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for old_serial in dict.fromkeys(old_serials):  # de-dupe, preserve order
            try:
                issue_result = cert_service.reissue_certificate(
                    session, pki_path, inter_cert, inter_key,
                    old_serial=old_serial, request_id=f"{batch_id}:{old_serial}",
                    export_password=export_password, issued_by=issued_by, days=days,
                )
            except cert_service.ReissueTargetError as e:
                result.rows.append(BatchRowResult(cn=old_serial, ok=False, error=str(e)))
                continue

            cert = issue_result.certificate
            result.rows.append(BatchRowResult(cn=cert.cn, ok=True, serial=cert.serial))
            if issue_result.bundle is not None:
                zf.writestr(f"{cert.cn}.p12", issue_result.bundle.data)
            manifest_rows.append((
                cert.cn,
                cert.serial,
                cert.expires_at.isoformat(),
                cert.employee_name or "",
                cert.device_type or "",
                cert.device_model or "",
                cert.device_mac or "",
                cert.device_serial or "",
                cert.subsidiary or "",
            ))

        manifest_buf = io.StringIO()
        writer = csv.writer(manifest_buf)
        writer.writerow(["cn", "serial", "expires_at", "employee_name", "device_type", "device_model", "device_mac", "device_serial", "subsidiary"])
        writer.writerows(manifest_rows)
        zf.writestr("manifest.csv", manifest_buf.getvalue())

    return result, zip_buf.getvalue()
