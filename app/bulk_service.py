"""Bulk reissue — handoff §6.5.

renew_batch is the bulk counterpart to a single reissue — pick a
selection of certs from the cert list (e.g. everything expiring soon)
and reissue all of them under one shared export password, same
partial-failure-doesn't-roll-back-the-rest rule a single reissue has.

The bulk *new-identity* issue path (CSV paste/upload, preview/confirm,
classify/issue_batch) that used to live in this file was removed: it
only ever produced certs with no subsidiary_id/network_role_id, so
they could never match a VLAN binding at RADIUS auth time. Real bulk
onboarding now lives in app/bulk_network_service.py
(/bulk/employees + /bulk/devices).
"""

from __future__ import annotations

import csv
import io
import zipfile
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app import cert_service


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
    the removed issue_batch so bulk_result.html can render either
    without knowing which one produced it."""
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
