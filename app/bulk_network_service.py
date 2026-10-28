"""Bulk onboarding for the real Employee/Device/Certificate chain —
app/bulk_service.py's CSV-bulk-issue is the older, disconnected path
(free-text subsidiary/employee_name, no subsidiary_id/network_role_id,
so a cert issued through it can never match a VLAN binding at
authentication time). This is the real one: Employees CSV first
(creates db.Employee rows), then a Devices CSV that looks each
employee up and issues a cert that actually carries subsidiary_id/
department_id/network_role_id/employee_id/device_id, same as a single
device issued by hand through the Employees UI.

Same preview-then-confirm shape as bulk_service.py, deliberately kept
simpler: no inline per-row fix-up, an invalid row just gets reported
with a reason and the admin re-uploads a corrected CSV. subsidiary/
department/role are referenced by *code* (not id), since that's what
an admin filling a spreadsheet by hand can actually type -- codes are
looked up live against the real tables, so a typo is caught here
rather than silently creating nothing.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, db, device_service, employee_service, network_policy

MAX_BATCH_SIZE = 200


class BatchTooLargeError(Exception):
    pass


@dataclass
class EmployeeInputRow:
    subsidiary_code: str
    department_code: str
    display_name: str
    employee_number: str | None = None


@dataclass
class EmployeePreviewRow:
    row: EmployeeInputRow
    classification: str  # "valid" | "duplicate" | "malformed"
    reason: str | None = None


@dataclass
class DeviceInputRow:
    subsidiary_code: str
    employee_number: str
    role_code: str
    device_type: str | None = None
    device_model: str | None = None
    mac_address: str | None = None
    serial_number: str | None = None


@dataclass
class DevicePreviewRow:
    row: DeviceInputRow
    classification: str  # "valid" | "malformed"
    reason: str | None = None
    employee_name: str | None = None


@dataclass
class BatchRowResult:
    label: str
    ok: bool
    detail: str | None = None
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


_EMPLOYEE_HEADER_ALIASES = {
    "subsidiary_code": {"subsidiary_code", "subsidiary", "company", "company code"},
    "department_code": {"department_code", "department", "dept", "dept code"},
    "display_name": {"display_name", "name", "employee_name", "employee name", "full name"},
    "employee_number": {"employee_number", "employee number", "employee #", "emp number", "id"},
}

_DEVICE_HEADER_ALIASES = {
    "subsidiary_code": {"subsidiary_code", "subsidiary", "company", "company code"},
    "employee_number": {"employee_number", "employee number", "employee #", "emp number", "id"},
    "role_code": {"role_code", "role", "network_role", "network role"},
    "device_type": {"device_type", "device type", "type"},
    "device_model": {"device_model", "device model", "model", "brand/model"},
    "mac_address": {"mac_address", "mac", "mac address", "device mac"},
    "serial_number": {"serial_number", "serial", "serial number", "asset tag"},
}


def _slugify_cn(*parts: str | None) -> str:
    raw = "-".join(p for p in parts if p).lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:63] or "device"


def _match_header(cell: str, aliases: dict[str, set[str]]) -> str | None:
    cell = cell.strip().lower()
    for field_name, names in aliases.items():
        if cell in names:
            return field_name
    return None


def parse_employee_csv(data: bytes) -> list[EmployeeInputRow]:
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    all_rows = [r for r in reader if any(c.strip() for c in r)]
    if not all_rows:
        return []

    header_map = {i: _match_header(cell, _EMPLOYEE_HEADER_ALIASES) for i, cell in enumerate(all_rows[0])}
    has_header = any(header_map.values())
    data_rows = all_rows[1:] if has_header else all_rows

    out = []
    for raw in data_rows:
        values = {}
        if has_header:
            for i, cell in enumerate(raw):
                field_name = header_map.get(i)
                if field_name:
                    values[field_name] = cell.strip()
        else:
            # Positional fallback: subsidiary_code, department_code, display_name, employee_number
            keys = ["subsidiary_code", "department_code", "display_name", "employee_number"]
            for i, cell in enumerate(raw):
                if i < len(keys):
                    values[keys[i]] = cell.strip()
        out.append(EmployeeInputRow(
            subsidiary_code=values.get("subsidiary_code", ""),
            department_code=values.get("department_code", ""),
            display_name=values.get("display_name", ""),
            employee_number=values.get("employee_number") or None,
        ))
    return out


def parse_device_csv(data: bytes) -> list[DeviceInputRow]:
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    all_rows = [r for r in reader if any(c.strip() for c in r)]
    if not all_rows:
        return []

    header_map = {i: _match_header(cell, _DEVICE_HEADER_ALIASES) for i, cell in enumerate(all_rows[0])}
    has_header = any(header_map.values())
    data_rows = all_rows[1:] if has_header else all_rows

    out = []
    for raw in data_rows:
        values = {}
        if has_header:
            for i, cell in enumerate(raw):
                field_name = header_map.get(i)
                if field_name:
                    values[field_name] = cell.strip()
        else:
            keys = ["subsidiary_code", "employee_number", "role_code", "device_type", "device_model", "mac_address", "serial_number"]
            for i, cell in enumerate(raw):
                if i < len(keys):
                    values[keys[i]] = cell.strip()
        out.append(DeviceInputRow(
            subsidiary_code=values.get("subsidiary_code", ""),
            employee_number=values.get("employee_number", ""),
            role_code=values.get("role_code", ""),
            device_type=values.get("device_type") or None,
            device_model=values.get("device_model") or None,
            mac_address=values.get("mac_address") or None,
            serial_number=values.get("serial_number") or None,
        ))
    return out


def classify_employees(session: Session, rows: list[EmployeeInputRow]) -> list[EmployeePreviewRow]:
    if len(rows) > MAX_BATCH_SIZE:
        raise BatchTooLargeError(f"batch of {len(rows)} exceeds cap of {MAX_BATCH_SIZE}")

    out = []
    for r in rows:
        if not r.display_name.strip():
            out.append(EmployeePreviewRow(r, "malformed", "missing display name"))
            continue
        if not r.subsidiary_code.strip():
            out.append(EmployeePreviewRow(r, "malformed", "missing subsidiary_code"))
            continue
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == r.subsidiary_code.strip().lower()))
        if not sub:
            out.append(EmployeePreviewRow(r, "malformed", f"unknown subsidiary_code '{r.subsidiary_code}'"))
            continue
        if not r.department_code.strip():
            out.append(EmployeePreviewRow(r, "malformed", "missing department_code"))
            continue
        dept = session.scalar(
            select(db.Department).where(
                db.Department.subsidiary_id == sub.id,
                db.Department.code == r.department_code.strip().lower(),
            )
        )
        if not dept:
            out.append(EmployeePreviewRow(r, "malformed", f"unknown department_code '{r.department_code}' in '{sub.code}'"))
            continue
        if r.employee_number:
            dup = session.scalar(
                select(db.Employee).where(
                    db.Employee.subsidiary_id == sub.id,
                    db.Employee.employee_number == r.employee_number,
                )
            )
            if dup:
                out.append(EmployeePreviewRow(r, "duplicate", f"employee_number '{r.employee_number}' already exists"))
                continue
        out.append(EmployeePreviewRow(r, "valid"))
    return out


def confirm_employees(actor: db.Admin, session: Session, rows: list[EmployeeInputRow], batch_id: str) -> BatchResult:
    result = BatchResult(batch_id=batch_id)
    for r in rows:
        label = r.employee_number or r.display_name
        try:
            sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == r.subsidiary_code.strip().lower()))
            if not sub:
                raise network_policy.PolicyValidationError(f"unknown subsidiary_code '{r.subsidiary_code}'")
            dept = session.scalar(
                select(db.Department).where(
                    db.Department.subsidiary_id == sub.id,
                    db.Department.code == r.department_code.strip().lower(),
                )
            )
            if not dept:
                raise network_policy.PolicyValidationError(f"unknown department_code '{r.department_code}'")
            emp = employee_service.create_employee(
                actor, sub.id, r.display_name, dept.id, r.employee_number, session,
            )
            session.commit()
            result.rows.append(BatchRowResult(label=label, ok=True, detail=emp.id))
        except Exception as e:  # noqa: BLE001 - one bad row must not sink the batch
            session.rollback()
            result.rows.append(BatchRowResult(label=label, ok=False, error=str(e)))
    return result


def classify_devices(session: Session, rows: list[DeviceInputRow]) -> list[DevicePreviewRow]:
    if len(rows) > MAX_BATCH_SIZE:
        raise BatchTooLargeError(f"batch of {len(rows)} exceeds cap of {MAX_BATCH_SIZE}")

    out = []
    for r in rows:
        if not r.subsidiary_code.strip() or not r.employee_number.strip() or not r.role_code.strip():
            out.append(DevicePreviewRow(r, "malformed", "missing subsidiary_code, employee_number, or role_code"))
            continue
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == r.subsidiary_code.strip().lower()))
        if not sub:
            out.append(DevicePreviewRow(r, "malformed", f"unknown subsidiary_code '{r.subsidiary_code}'"))
            continue
        emp = session.scalar(
            select(db.Employee).where(
                db.Employee.subsidiary_id == sub.id,
                db.Employee.employee_number == r.employee_number.strip(),
            )
        )
        if not emp:
            out.append(DevicePreviewRow(r, "malformed", f"no employee with employee_number '{r.employee_number}' in '{sub.code}' (create it via the Employees CSV first)"))
            continue
        role = session.scalar(
            select(db.NetworkRole).where(
                db.NetworkRole.subsidiary_id == sub.id,
                db.NetworkRole.code == r.role_code.strip().lower(),
            )
        )
        if not role:
            out.append(DevicePreviewRow(r, "malformed", f"unknown role_code '{r.role_code}' in '{sub.code}'"))
            continue
        pairing = session.scalar(
            select(db.DepartmentRole).where(
                db.DepartmentRole.department_id == emp.department_id,
                db.DepartmentRole.network_role_id == role.id,
            )
        )
        if not pairing:
            out.append(DevicePreviewRow(r, "malformed", f"role '{role.code}' is not linked to {emp.display_name}'s department", employee_name=emp.display_name))
            continue
        out.append(DevicePreviewRow(r, "valid", employee_name=emp.display_name))
    return out


def confirm_devices(
    actor: db.Admin,
    session: Session,
    pki_path,
    inter_cert,
    inter_key,
    rows: list[DeviceInputRow],
    batch_id: str,
    export_password: str,
    days: int,
) -> tuple[BatchResult, bytes]:
    """Registers each device, then issues a real cert against it
    (subsidiary_id/department_id/network_role_id/employee_id/device_id
    all signed in) -- unlike bulk_service.issue_batch, this produces
    certs that actually match a VLAN binding at auth time."""
    result = BatchResult(batch_id=batch_id)
    zip_buf = io.BytesIO()
    manifest_rows = []

    with cert_service._lock(pki_path):
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for r in rows:
                label = f"{r.employee_number}:{r.device_type or 'device'}"
                try:
                    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == r.subsidiary_code.strip().lower()))
                    emp = session.scalar(
                        select(db.Employee).where(
                            db.Employee.subsidiary_id == sub.id,
                            db.Employee.employee_number == r.employee_number.strip(),
                        )
                    )
                    role = session.scalar(
                        select(db.NetworkRole).where(
                            db.NetworkRole.subsidiary_id == sub.id,
                            db.NetworkRole.code == r.role_code.strip().lower(),
                        )
                    )
                    device_name = f"{emp.display_name}-{r.device_type or 'device'}"
                    cn = _slugify_cn(emp.employee_number or emp.display_name, r.device_type or "device")
                    device = device_service.register_device(
                        actor, emp.id, device_name, emp.department_id, role.id, session,
                        device_type=r.device_type, device_model=r.device_model,
                        serial_number=r.serial_number, mac_address=r.mac_address,
                    )
                    session.commit()

                    assignment = cert_service.NetworkAssignment(
                        subsidiary_id=sub.id, department_id=emp.department_id,
                        network_role_id=role.id, employee_id=emp.id, device_id=device.id,
                    )
                    device_info = cert_service.DeviceInfo(
                        employee_name=emp.display_name, device_type=r.device_type,
                        device_model=r.device_model, device_mac=r.mac_address,
                        device_serial=r.serial_number, subsidiary=sub.display_name,
                    )
                    issue_result = cert_service._issue_one_locked(
                        session, pki_path, inter_cert, inter_key,
                        cn=cn, note=f"Bulk-issued for {emp.display_name}",
                        request_id=f"{batch_id}:{device.id}",
                        export_password=export_password, issued_by=actor.username,
                        days=days, batch_id=batch_id, device=device_info,
                        assignment=assignment,
                    )
                    session.commit()

                    cert = issue_result.certificate
                    result.rows.append(BatchRowResult(label=label, ok=True, detail=cert.serial))
                    if issue_result.bundle is not None:
                        zf.writestr(f"{device_name}.p12", issue_result.bundle.data)
                    manifest_rows.append((device.id, cert.serial, cert.expires_at.isoformat(), emp.display_name, device_name, r.device_type or "", r.mac_address or ""))
                except Exception as e:  # noqa: BLE001 - one bad row must not sink the batch
                    session.rollback()
                    result.rows.append(BatchRowResult(label=label, ok=False, error=str(e)))

            manifest_buf = io.StringIO()
            writer = csv.writer(manifest_buf)
            writer.writerow(["device_id", "serial", "expires_at", "employee_name", "device_name", "device_type", "mac_address"])
            writer.writerows(manifest_rows)
            zf.writestr("manifest.csv", manifest_buf.getvalue())

    return result, zip_buf.getvalue()
