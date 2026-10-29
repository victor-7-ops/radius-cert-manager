"""Server-rendered certificate routes (Jinja2 + HTMX) — handoff §6.

Suspend is available to Admin; unsuspend and revoke require Super Admin
(handoff §7). Buttons the current role can't use are absent from the
template context entirely, not rendered-and-disabled.

Split out of app/routes/web.py — see app/routes/web_helpers.py for the
shared formatting/scope helpers used across the web_*.py modules.
"""

from __future__ import annotations

import csv
import datetime
import io
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select

from app import auth, bulk_service, cert_service, crl_health, db, network_policy, rate_limit
from app.routes import web_helpers as h
from app.validation import CN_RE, normalize_employee_key, normalize_mac


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-certs"])

    _crl_banner_context = crl_health.banner_context

    def _slugify(name: str) -> str:
        import re

        return re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-") or "device"

    def _cert_filter_stmt(q, status, employee, subsidiary, admin=None):
        """Shared by the list page and the CSV export so the two can
        never silently drift apart on what a filter means."""
        stmt = select(db.Certificate).where(db.Certificate.cert_type == "client")
        if admin is not None and admin.subsidiary_scope:
            # Scoped admin: hard-filter to their own subsidiary regardless
            # of what's in the query string — this is the enforcement
            # point, the UI-level subsidiary filter is just a convenience.
            stmt = stmt.where(db.Certificate.subsidiary == admin.subsidiary_scope)
        if q:
            normalized_mac = normalize_mac(q)
            match = (
                db.Certificate.cn.contains(q)
                | db.Certificate.employee_name.contains(q)
                | db.Certificate.device_serial.contains(q)
                | db.Certificate.device_model.contains(q)
            )
            if normalized_mac:
                # MAC can be typed in any of the formats normalize_mac
                # accepts (colon/dash/Cisco-dotted/bare-hex) — normalize
                # the query the same way the stored value was normalized
                # at issue time so any of those formats finds it.
                match = match | (db.Certificate.device_mac == normalized_mac)
            else:
                match = match | db.Certificate.device_mac.contains(q)
            stmt = stmt.where(match)
        if employee:
            # Drill-down from an employee name elsewhere in the UI — all
            # of that person's devices, any status, so it reads as their
            # full device roster rather than just what's currently active.
            # Matched on employee_key (HANDOFF-LIFECYCLE.md §1.1), not the
            # exact employee_name string, so "Juan Dela Cruz" and "juan
            # dela cruz" don't silently split into two different rosters.
            stmt = stmt.where(db.Certificate.employee_key == normalize_employee_key(employee))
        if subsidiary:
            stmt = stmt.where(db.Certificate.subsidiary == subsidiary)
        if status == "expired":
            # "Expired" isn't a stored status (handoff §5.2) — it's an
            # active cert whose expires_at has passed.
            now = datetime.datetime.now(datetime.timezone.utc)
            stmt = stmt.where(db.Certificate.status == db.CertStatus.active, db.Certificate.expires_at < now)
        elif status == "active":
            # An expired-but-stored-active cert shows the "Expired" badge
            # (h.effective_status), so the Active filter must exclude it —
            # otherwise a row filtered into "Active" would render as
            # "Expired", which reads as a bug.
            now = datetime.datetime.now(datetime.timezone.utc)
            stmt = stmt.where(db.Certificate.status == db.CertStatus.active, db.Certificate.expires_at >= now)
        elif status:
            stmt = stmt.where(db.Certificate.status == status)
        return stmt.order_by(db.Certificate.issued_at.desc())

    @router.get("/certs")
    def cert_list(
        request: Request,
        q: str | None = None,
        status: str | None = None,
        employee: str | None = None,
        subsidiary: str | None = None,
        page: int = 1,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        page_size = 50
        stmt = _cert_filter_stmt(q, status, employee, subsidiary, admin).offset((page - 1) * page_size).limit(page_size)
        rows = session.scalars(stmt).all()

        items = [
            {
                "cn": c.cn,
                "serial": c.serial,
                "status": h.effective_status(c),
                "issued_at": c.issued_at.date(),
                "expires_relative": h.relative_expiry(c.expires_at),
                "issued_by": c.issued_by,
                "employee_name": c.employee_name,
                "device_type": c.device_type,
                "device_model": c.device_model,
                "device_mac": c.device_mac,
                "device_serial": c.device_serial,
                "subsidiary": c.subsidiary,
            }
            for c in rows
        ]
        return templates.TemplateResponse(
            request,
            "cert_list.html",
            {
                "admin": admin,
                "items": items,
                "q": q,
                "status_filter": status,
                "employee_filter": employee,
                "subsidiary_filter": admin.subsidiary_scope or subsidiary,
                "subsidiaries": [admin.subsidiary_scope] if admin.subsidiary_scope else db.active_subsidiary_names(session),
                **_crl_banner_context(session),
            },
        )

    @router.get("/certs/export.csv")
    def cert_export(
        q: str | None = None,
        status: str | None = None,
        employee: str | None = None,
        subsidiary: str | None = None,
        admin: db.Admin = Depends(deps.require_write),
    ):
        if rate_limit.is_rate_limited(f"export:{admin.id}", max_requests=10, window_seconds=300):
            # 429 literal, not status.HTTP_429_TOO_MANY_REQUESTS — this
            # function's own `status` query param (cert status filter)
            # shadows the fastapi.status module import within this scope.
            raise HTTPException(429, "Too many exports — wait a few minutes and try again.")
        # Whatever filter the admin currently has applied on the list
        # page — the export is "what I'm looking at", not "everything".
        session = deps.get_db_session()
        rows = session.scalars(_cert_filter_stmt(q, status, employee, subsidiary, admin)).all()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "cn", "serial", "status", "issued_at", "expires_at", "issued_by",
            "employee_name", "device_type", "device_model", "device_mac", "device_serial", "subsidiary",
        ])
        for c in rows:
            writer.writerow([
                c.cn, c.serial, h.effective_status(c), c.issued_at.isoformat(), c.expires_at.isoformat(),
                c.issued_by, c.employee_name or "", c.device_type or "", c.device_model or "", c.device_mac or "",
                c.device_serial or "", c.subsidiary or "",
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="certificates.csv"'},
        )

    @router.get("/certs/check-cn")
    def check_cn(request: Request, cn: str = "", admin: db.Admin = Depends(deps.require_admin)):
        if not cn:
            return HTMLResponse("")
        if not CN_RE.match(cn):
            return HTMLResponse('<span class="text-red-600">Invalid characters — use letters, numbers, dot, dash, underscore.</span>')
        session = deps.get_db_session()
        existing = session.scalar(
            select(db.Certificate).where(
                db.Certificate.cn == cn,
                db.Certificate.status == db.CertStatus.active,
                db.Certificate.cert_type == "client",
            )
        )
        if existing is not None:
            return HTMLResponse(f'<span class="text-red-600">An active certificate for "{cn}" already exists.</span>')
        return HTMLResponse('<span class="text-green-600">Available.</span>')

    @router.get("/certs/issue")
    def issue_form(
        request: Request,
        device_id: str | None = None,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        device = session.get(db.Device, device_id) if device_id else None
        form_data = {"subsidiary": admin.subsidiary_scope} if admin.subsidiary_scope else {}
        if device:
            network_policy.assert_can_manage_subsidiary(admin, device.subsidiary_id, session)
            sub = session.get(db.Subsidiary, device.subsidiary_id)
            form_data.update({
                "cn": device.asset_tag or device.display_name.lower().replace(" ", "-"),
                "employee_name": device.employee.display_name if device.employee else "",
                "device_type": device.device_type or "",
                "device_model": device.device_model or "",
                "device_mac": device.mac_address or "",
                "device_serial": device.serial_number or device.asset_tag or "",
                "subsidiary": sub.display_name if sub else "",
            })

        return templates.TemplateResponse(
            request,
            "issue.html",
            {
                "admin": admin,
                "request_id": str(uuid.uuid4()),
                "device_types": db.DEVICE_TYPES,
                "subsidiaries": [admin.subsidiary_scope] if admin.subsidiary_scope else db.active_subsidiary_names(session),
                "form": form_data if form_data else None,
                "device": device,
                **_crl_banner_context(session),
            },
        )

    @router.post("/certs/issue")
    def issue_submit(
        request: Request,
        cn: str = Form(...),
        note: str = Form(""),
        employee_name: str = Form(""),
        device_type: str = Form(""),
        device_model: str = Form(""),
        device_mac: str = Form(""),
        device_serial: str = Form(""),
        subsidiary: str = Form(""),
        request_id: str = Form(...),
        confirm_duplicate: str = Form(""),
        device_id: str = Form(""),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session = deps.get_db_session()
        device = session.get(db.Device, device_id) if device_id else None
        if device:
            network_policy.assert_can_manage_subsidiary(admin, device.subsidiary_id, session)

        if admin.subsidiary_scope:
            # Scoped admin: the subsidiary isn't a free-text choice, it's
            # who they are. Ignore whatever the form sent (hidden/disabled
            # client-side, but never trust that alone) and force it.
            subsidiary = admin.subsidiary_scope
        form_context = {
            "admin": admin,
            "request_id": request_id,
            "device_types": db.DEVICE_TYPES,
            "subsidiaries": [admin.subsidiary_scope] if admin.subsidiary_scope else db.active_subsidiary_names(session),
            "device": device,
            "form": {
                "cn": cn,
                "employee_name": employee_name,
                "device_type": device_type,
                "device_model": device_model,
                "device_mac": device_mac,
                "device_serial": device_serial,
                "subsidiary": subsidiary,
                "note": note,
                "device_id": device_id,
            },
            **_crl_banner_context(session),
        }
        if not CN_RE.match(cn):
            return templates.TemplateResponse(
                request, "issue.html", {**form_context, "error": "Invalid CN format."}, status_code=400,
            )
        normalized_mac = None
        if device_mac.strip():
            normalized_mac = normalize_mac(device_mac.strip())
            if normalized_mac is None:
                return templates.TemplateResponse(
                    request,
                    "issue.html",
                    {**form_context, "error": "Invalid MAC address format."},
                    status_code=400,
                )

        stripped_subsidiary = subsidiary.strip() or None
        if stripped_subsidiary is not None and stripped_subsidiary not in db.active_subsidiary_names(session):
            return templates.TemplateResponse(
                request, "issue.html", {**form_context, "error": "Invalid subsidiary."}, status_code=400,
            )

        stripped_serial = device_serial.strip()
        if (normalized_mac or stripped_serial) and not confirm_duplicate:
            # A reused MAC/serial usually means a typo or a device that
            # was never decommissioned in this system, not an intentional
            # reissue — flag it but let the admin push through anyway,
            # since a legitimate reuse (repurposed hardware) does happen.
            conds = []
            if normalized_mac:
                conds.append(db.Certificate.device_mac == normalized_mac)
            if stripped_serial:
                conds.append(db.Certificate.device_serial == stripped_serial)
            duplicates = session.scalars(
                select(db.Certificate).where(
                    db.Certificate.status == db.CertStatus.active,
                    db.Certificate.cert_type == "client",
                    or_(*conds),
                )
            ).all()
            if duplicates:
                return templates.TemplateResponse(
                    request,
                    "issue.html",
                    {**form_context, "duplicate_matches": duplicates},
                )

        stripped_employee_name = employee_name.strip()
        if stripped_employee_name and not confirm_duplicate:
            # HANDOFF-LIFECYCLE.md §1.1: warn, don't block, if this name
            # normalizes to an employee_key that's already on record under
            # a different exact spelling — "Juan Dela Cruz" typed against
            # an existing "juan dela cruz" is very likely the same person,
            # and a silent second spelling is exactly what later splits
            # them into two people for offboarding purposes.
            entered_key = normalize_employee_key(stripped_employee_name)
            existing_spellings = sorted(
                {
                    name
                    for (name,) in session.execute(
                        select(db.Certificate.employee_name).where(
                            db.Certificate.employee_key == entered_key,
                            db.Certificate.employee_name != stripped_employee_name,
                        )
                    ).all()
                }
            )
            if existing_spellings:
                return templates.TemplateResponse(
                    request,
                    "issue.html",
                    {**form_context, "employee_spelling_matches": existing_spellings},
                )

        assignment = None
        if device:
            assignment = cert_service.NetworkAssignment(
                subsidiary_id=device.subsidiary_id,
                department_id=device.department_id,
                network_role_id=device.network_role_id,
                employee_id=device.employee_id,
                device_id=device.id,
            )

        try:
            result = cert_service.issue_certificate(
                session,
                deps.pki_path,
                deps.inter_cert,
                deps.inter_key,
                cn=cn,
                note=note or None,
                request_id=request_id,
                export_password=None,
                issued_by=admin.username,
                days=deps.client_cert_days,
                device=cert_service.DeviceInfo(
                    employee_name=employee_name.strip() or None,
                    device_type=device_type.strip() or None,
                    device_model=device_model.strip() or None,
                    device_mac=normalized_mac,
                    device_serial=device_serial.strip() or None,
                    subsidiary=stripped_subsidiary,
                ),
                assignment=assignment,
            )
        except cert_service.CNConflictError:
            return templates.TemplateResponse(
                request,
                "issue.html",
                {**form_context, "error": f'An active certificate for "{cn}" already exists.'},
                status_code=409,
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request,
                "issue.html",
                {**form_context, "error": str(e)},
                status_code=400,
            )
        if result.bundle is None:
            # Deduped on request_id (HANDOFF-FLEET.md: prevents a
            # timeout-and-retry from minting two certs) -- the private
            # key only ever existed in the first issuance's response, so
            # there is nothing left to deliver. Flag it instead of
            # silently dropping the user on a cert page with no
            # explanation for why there's no download link.
            return RedirectResponse(f"/certs/{result.certificate.serial}?no_bundle=1", status_code=303)
        deps.store_pending_bundle(result.certificate.serial, result.bundle)
        deps.store_pending_password(result.certificate.serial, result.bundle.password)
        return RedirectResponse(f"/certs/{result.certificate.serial}/delivery", status_code=303)

    @router.get("/certs/{serial}/delivery")
    def delivery(request: Request, serial: str, admin: db.Admin = Depends(deps.require_write)):
        # Reloadable: the password/link stay available as long as the
        # bundle itself hasn't actually been downloaded yet (see
        # take_pending_bundle), so an admin can revisit this page --
        # e.g. after a QR token expires before anyone scanned it --
        # without needing to reissue the whole certificate.
        password = deps.peek_pending_password(serial)
        if password is None or not deps.peek_pending_bundle(serial):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "nothing to deliver")
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is not None:
            h.require_cert_scope(admin, cert)

        # The device that needs the .p12 usually isn't logged into this
        # app (an employee's phone, not the admin's browser), so the QR
        # carries its own short-lived signed token instead of relying on
        # the admin session cookie. The bundle itself stays single-use —
        # whichever of "Download .p12" or the QR scan happens first wins.
        qr_token = auth.make_bundle_qr_token(deps.secret_key, serial)
        base = str(request.base_url).rstrip("/")
        qr_url = f"{base}/certs/{serial}/bundle/qr?token={qr_token}"
        qr_mc_url = f"{base}/certs/{serial}/mobileconfig/qr?token={qr_token}"
        install_url = f"{base}/certs/{serial}/install?token={qr_token}"

        return templates.TemplateResponse(
            request,
            "delivery.html",
            {
                "admin": admin,
                "cn": cert.cn,
                "serial": serial,
                "export_password": password,
                "qr_svg": h.qr_svg(qr_url),
                "qr_mobileconfig_svg": h.qr_svg(qr_mc_url),
                "qr_install_svg": h.qr_svg(install_url),
                "install_url": install_url,
                "qr_expires_minutes": auth.BUNDLE_QR_TOKEN_MAX_AGE_SECONDS // 60,
                **_crl_banner_context(session),
            },
        )

    @router.get("/certs/{serial}/bundle/qr")
    def download_bundle_via_qr(request: Request, serial: str, token: str = ""):
        # No auth on this route by design (see delivery() above) — rate
        # limit by IP instead of admin id, since there's no admin here.
        ip = request.client.host if request.client else "unknown"
        if rate_limit.is_rate_limited(f"bundle-qr:{ip}", max_requests=20, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        if auth.verify_bundle_qr_token(deps.secret_key, token) != serial:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or expired QR link")
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")
        return Response(
            content=bundle.data,
            media_type="application/x-pkcs12",
            headers={"Content-Disposition": f'attachment; filename="{serial}.p12"'},
        )

    @router.get("/certs/{serial}/mobileconfig/qr")
    def download_mobileconfig_via_qr(request: Request, serial: str, token: str = ""):
        ip = request.client.host if request.client else "unknown"
        if rate_limit.is_rate_limited(f"bundle-qr:{ip}", max_requests=20, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        if auth.verify_bundle_qr_token(deps.secret_key, token) != serial:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or expired QR link")
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")
        from app import mobileconfig

        wifi_ssid = getattr(deps.settings, "wifi_ssid", "Corporate-WiFi")
        cfg_bytes = mobileconfig.generate_mobileconfig(
            cn=cert.cn,
            serial=serial,
            pkcs12_data=bundle.data,
            ca_cert=deps.inter_cert,
            wifi_ssid=wifi_ssid,
            export_password=bundle.password,
            organization=cert.subsidiary,
        )
        return Response(
            content=cfg_bytes,
            media_type="application/x-apple-as-config",
            headers={"Content-Disposition": f'attachment; filename="{cert.cn}.mobileconfig"'},
        )

    @router.get("/certs/{serial}/bundle")
    def download_bundle(serial: str, admin: db.Admin = Depends(deps.require_write)):
        if rate_limit.is_rate_limited(f"bundle:{admin.id}", max_requests=30, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        if admin.subsidiary_scope:
            session = deps.get_db_session()
            cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
            if cert is not None:
                h.require_cert_scope(admin, cert)
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")
        return Response(
            content=bundle.data,
            media_type="application/x-pkcs12",
            headers={"Content-Disposition": f'attachment; filename="{serial}.p12"'},
        )

    @router.get("/certs/{serial}/mobileconfig")
    def download_mobileconfig(serial: str, admin: db.Admin = Depends(deps.require_write)):
        if rate_limit.is_rate_limited(f"bundle:{admin.id}", max_requests=30, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        if admin.subsidiary_scope:
            h.require_cert_scope(admin, cert)
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")
        from app import mobileconfig

        wifi_ssid = getattr(deps.settings, "wifi_ssid", "Corporate-WiFi")
        cfg_bytes = mobileconfig.generate_mobileconfig(
            cn=cert.cn,
            serial=serial,
            pkcs12_data=bundle.data,
            ca_cert=deps.inter_cert,
            wifi_ssid=wifi_ssid,
            export_password=bundle.password,
            organization=cert.subsidiary,
        )
        return Response(
            content=cfg_bytes,
            media_type="application/x-apple-as-config",
            headers={"Content-Disposition": f'attachment; filename="{cert.cn}.mobileconfig"'},
        )

    @router.get("/certs/{serial}/windows-profile")
    def download_windows_profile(serial: str, admin: db.Admin = Depends(deps.require_write)):
        if rate_limit.is_rate_limited(f"bundle:{admin.id}", max_requests=30, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        if admin.subsidiary_scope:
            h.require_cert_scope(admin, cert)
        from app import windows_profile

        wifi_ssid = getattr(deps.settings, "wifi_ssid", "Corporate-WiFi")
        xml_content = windows_profile.generate_windows_wifi_xml(
            ssid=wifi_ssid,
            ca_cert=deps.inter_cert,
        )
        return Response(
            content=xml_content,
            media_type="application/x-wifi-config",
            headers={"Content-Disposition": f'attachment; filename="{wifi_ssid}-Profile.xml"'},
        )

    def _build_onboard_zip(cert: db.Certificate, bundle) -> tuple[bytes, str]:
        """Everything needed to onboard a device in one zip: one-click
        installers for Windows and Linux, plus the .mobileconfig for
        macOS/iOS (which can also install standalone, true one-click,
        without needing the zip at all)."""
        from app import mobileconfig, pki, windows_profile
        import io
        import zipfile

        wifi_ssid = getattr(deps.settings, "wifi_ssid", "Corporate-WiFi")
        xml_content = windows_profile.generate_windows_wifi_xml(ssid=wifi_ssid, ca_cert=deps.inter_cert)
        ca_pem = pki.cert_to_pem(deps.inter_cert)
        mc_bytes = mobileconfig.generate_mobileconfig(
            cn=cert.cn,
            serial=cert.serial,
            pkcs12_data=bundle.data,
            ca_cert=deps.inter_cert,
            wifi_ssid=wifi_ssid,
            export_password=bundle.password,
            organization=cert.subsidiary,
        )

        folder_name = _slugify(cert.employee_name or cert.cn)
        p12_name = f"{cert.cn}.p12"
        xml_name = f"{wifi_ssid}-Profile.xml"
        ca_name = "ca.pem"

        # Password is plaintext in both scripts by design (user explicitly
        # chose this tradeoff over typing it manually, after being told
        # protection then rests on how the zip itself is distributed); it
        # never leaves this zip.

        # certutil -user writes to the *current user's* cert store, so this
        # needs no admin elevation/UAC prompt.
        install_cmd = (
            "@echo off\r\n"
            "cd /d \"%~dp0\"\r\n"
            f'certutil -f -user -p "{bundle.password}" -importPFX My "{p12_name}"\r\n'
            "if errorlevel 1 (\r\n"
            "  echo Certificate import failed. Contact IT.\r\n"
            "  pause\r\n"
            "  exit /b 1\r\n"
            ")\r\n"
            f'netsh wlan add profile filename="{xml_name}" user=current\r\n'
            "echo Done. Connecting to Wi-Fi...\r\n"
            f'netsh wlan connect name="{wifi_ssid}"\r\n'
            "pause\r\n"
        )

        # nmcli (NetworkManager, the default on Ubuntu/Fedora/Debian
        # desktops) takes the .p12 directly for both client-cert and
        # private-key -- no separate PEM extraction needed.
        install_sh = (
            "#!/bin/sh\n"
            "set -e\n"
            'cd "$(dirname "$0")"\n'
            "if ! command -v nmcli >/dev/null; then\n"
            '  echo "nmcli (NetworkManager) not found -- ask IT for manual setup."\n'
            "  exit 1\n"
            "fi\n"
            f'nmcli connection delete "{wifi_ssid}" 2>/dev/null || true\n'
            f'nmcli connection add type wifi con-name "{wifi_ssid}" ssid "{wifi_ssid}" \\\n'
            "  wifi-sec.key-mgmt wpa-eap 802-1x.eap tls \\\n"
            f'  802-1x.identity "{cert.cn}" \\\n'
            f'  802-1x.ca-cert "$(pwd)/{ca_name}" \\\n'
            f'  802-1x.client-cert "$(pwd)/{p12_name}" \\\n'
            f'  802-1x.private-key "$(pwd)/{p12_name}" \\\n'
            f'  802-1x.private-key-password "{bundle.password}"\n'
            f'nmcli connection up "{wifi_ssid}"\n'
            'echo "Connected."\n'
        )

        mc_name = f"{cert.cn}.mobileconfig"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{folder_name}/{p12_name}", bundle.data)
            zf.writestr(f"{folder_name}/{xml_name}", xml_content)
            zf.writestr(f"{folder_name}/{ca_name}", ca_pem)
            zf.writestr(f"{folder_name}/{mc_name}", mc_bytes)
            zf.writestr(f"{folder_name}/Install.cmd", install_cmd)
            info = zipfile.ZipInfo(f"{folder_name}/install.sh")
            info.external_attr = 0o755 << 16  # executable bit, for unzip -X / Linux
            zf.writestr(info, install_sh)
            zf.writestr(
                f"{folder_name}/README.txt",
                "Windows: double-click Install.cmd.\n"
                "Linux: run ./install.sh (chmod +x install.sh first if needed).\n"
                f"macOS/iOS: open {mc_name}, tap Install in Settings.\n"
                f"All three install the certificate and connect to {wifi_ssid} automatically.\n",
            )
        return buf.getvalue(), folder_name

    @router.get("/certs/{serial}/onboard-bundle")
    def download_onboard_bundle(serial: str, admin: db.Admin = Depends(deps.require_write)):
        if rate_limit.is_rate_limited(f"bundle:{admin.id}", max_requests=30, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        if admin.subsidiary_scope:
            h.require_cert_scope(admin, cert)
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")
        zip_bytes, folder_name = _build_onboard_zip(cert, bundle)
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{folder_name}.zip"'},
        )

    @router.get("/certs/{serial}/install")
    def smart_install(request: Request, serial: str, token: str = ""):
        """One link/QR for the employee's own device: no admin login, no
        platform picking. Detects the device's OS from its own request
        and serves the single right thing -- .mobileconfig (true
        one-click on Apple) or the all-in-one zip (Windows/Linux/
        anything else) -- so there is exactly one thing to hand out."""
        ip = request.client.host if request.client else "unknown"
        if rate_limit.is_rate_limited(f"bundle-qr:{ip}", max_requests=20, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        if auth.verify_bundle_qr_token(deps.secret_key, token) != serial:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid or expired link")
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")

        ua = (request.headers.get("user-agent") or "").lower()
        is_apple = any(tok in ua for tok in ("iphone", "ipad", "macintosh", "mac os x"))
        if is_apple:
            from app import mobileconfig

            wifi_ssid = getattr(deps.settings, "wifi_ssid", "Corporate-WiFi")
            cfg_bytes = mobileconfig.generate_mobileconfig(
                cn=cert.cn,
                serial=serial,
                pkcs12_data=bundle.data,
                ca_cert=deps.inter_cert,
                wifi_ssid=wifi_ssid,
                export_password=bundle.password,
                organization=cert.subsidiary,
            )
            return Response(
                content=cfg_bytes,
                media_type="application/x-apple-as-config",
                headers={"Content-Disposition": f'attachment; filename="{cert.cn}.mobileconfig"'},
            )

        zip_bytes, folder_name = _build_onboard_zip(cert, bundle)
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{folder_name}.zip"'},
        )

    @router.get("/certs/{serial}")
    def cert_detail(request: Request, serial: str, no_bundle: str = "", admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        h.require_cert_scope(admin, cert)

        history_rows = session.scalars(
            select(db.AuditLog)
            .where(db.AuditLog.target == cert.cn)
            .order_by(db.AuditLog.timestamp.desc())
        ).all()

        supersedes = session.get(db.Certificate, cert.supersedes_id) if cert.supersedes_id else None
        superseded_by = session.scalar(
            select(db.Certificate).where(db.Certificate.supersedes_id == cert.id)
        )

        other_device_count = 0
        if cert.employee_key:
            other_device_count = session.scalar(
                select(func.count()).select_from(db.Certificate).where(
                    db.Certificate.employee_key == cert.employee_key,
                    db.Certificate.id != cert.id,
                )
            )

        is_super = admin.role == db.AdminRole.super_admin
        return templates.TemplateResponse(
            request,
            "cert_detail.html",
            {
                "admin": admin,
                "no_bundle_notice": bool(no_bundle),
                "cert": {
                    "cn": cert.cn,
                    "serial": cert.serial,
                    "status": h.effective_status(cert),
                    "issued_at": cert.issued_at,
                    "expires_at": cert.expires_at,
                    "issued_by": cert.issued_by,
                    "note": cert.note,
                    "employee_name": cert.employee_name,
                    "device_type": cert.device_type,
                    "device_model": cert.device_model,
                    "device_mac": cert.device_mac,
                    "device_serial": cert.device_serial,
                    "subsidiary": cert.subsidiary,
                    "supersedes_cn": supersedes.cn if supersedes else None,
                    "supersedes_serial": supersedes.serial if supersedes else None,
                    "superseded_by_cn": superseded_by.cn if superseded_by else None,
                    "superseded_by_serial": superseded_by.serial if superseded_by else None,
                },
                "history": [
                    {"action": hh.action, "actor": hh.actor, "detail": hh.detail, "timestamp": hh.timestamp}
                    for hh in history_rows
                ],
                "can_suspend": True,
                "can_unsuspend": is_super,
                "can_revoke": is_super,
                "other_device_count": other_device_count,
                **_crl_banner_context(session),
            },
        )

    def _load_cert_or_404_in_scope(session, admin: db.Admin, serial: str) -> db.Certificate:
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        h.require_cert_scope(admin, cert)
        return cert

    @router.post("/certs/{serial}/reissue")
    def reissue(request: Request, serial: str, admin: db.Admin = Depends(deps.require_write)):
        session = deps.get_db_session()
        _load_cert_or_404_in_scope(session, admin, serial)
        try:
            result = cert_service.reissue_certificate(
                session,
                deps.pki_path,
                deps.inter_cert,
                deps.inter_key,
                old_serial=serial,
                request_id=str(uuid.uuid4()),
                export_password=None,
                issued_by=admin.username,
                days=deps.client_cert_days,
            )
        except cert_service.ReissueTargetError as e:
            raise HTTPException(status.HTTP_409_CONFLICT, str(e))
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
        deps.store_pending_bundle(result.certificate.serial, result.bundle)
        deps.store_pending_password(result.certificate.serial, result.bundle.password)
        return RedirectResponse(f"/certs/{result.certificate.serial}/delivery", status_code=303)

    @router.post("/certs/{serial}/suspend")
    def suspend(request: Request, serial: str, reason: str = "", admin: db.Admin = Depends(deps.require_write)):
        session = deps.get_db_session()
        _load_cert_or_404_in_scope(session, admin, serial)
        try:
            cert = cert_service.suspend(session, deps.pki_path, serial, reason or "not specified", admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        dest = request.headers.get("referer", "/certs")
        return RedirectResponse(h.flash(dest, f"{cert.cn} suspended.", "warn"), status_code=303)

    @router.post("/certs/{serial}/unsuspend")
    def unsuspend(request: Request, serial: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        _load_cert_or_404_in_scope(session, admin, serial)
        try:
            cert = cert_service.unsuspend(session, deps.pki_path, serial, admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return RedirectResponse(h.flash(f"/certs/{serial}", f"{cert.cn} unsuspended.", "success"), status_code=303)

    @router.post("/certs/{serial}/revoke")
    def revoke(request: Request, serial: str, reason: str = "", admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        _load_cert_or_404_in_scope(session, admin, serial)
        try:
            cert = cert_service.revoke(session, deps.pki_path, serial, reason or "not specified", admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return RedirectResponse(h.flash(f"/certs/{serial}", f"{cert.cn} revoked.", "danger"), status_code=303)

    @router.post("/certs/bulk-action")
    def cert_bulk_action(
        request: Request,
        serials: list[str] = Form(...),
        bulk_action: str = Form(..., alias="action"),
        reason: str = "",
        export_password: str = Form(""),
        admin: db.Admin = Depends(deps.require_write),
    ):
        if bulk_action not in ("suspend", "revoke", "renew"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid action")
        if bulk_action == "revoke" and admin.role != db.AdminRole.super_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "only a super admin can revoke")

        session = deps.get_db_session()

        if bulk_action == "renew":
            if len(export_password) < 12:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "export password must be at least 12 characters")
            in_scope_serials = []
            for serial in dict.fromkeys(serials):  # de-dupe, preserve order
                cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
                if cert is None:
                    continue
                # Same silent-skip-out-of-scope rule as suspend/revoke
                # below — the checkbox UI is already scope-filtered.
                if admin.subsidiary_scope and cert.subsidiary != admin.subsidiary_scope:
                    continue
                in_scope_serials.append(serial)
            batch_id = str(uuid.uuid4())
            result, zip_bytes = bulk_service.renew_batch(
                session, deps.pki_path, deps.inter_cert, deps.inter_key,
                in_scope_serials, batch_id=batch_id, export_password=export_password,
                issued_by=admin.username, days=deps.client_cert_days,
            )
            deps.store_pending_batch(batch_id, result, zip_bytes)
            # Reissue doesn't touch the old cert's status (handoff §8.1 —
            # coexistence until an admin separately suspends/revokes the
            # old one), so unlike suspend/revoke there's nothing new for
            # the CRL to reflect here.
            return RedirectResponse(f"/certs/bulk/{batch_id}", status_code=303)

        fn = cert_service.suspend if bulk_action == "suspend" else cert_service.revoke
        done = 0
        missing = 0
        for serial in dict.fromkeys(serials):  # de-dupe, preserve order
            cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
            if cert is None:
                missing += 1
                continue
            # Silently skip out-of-scope certs rather than 403ing the
            # whole batch — the checkbox UI is already scope-filtered, so
            # this only fires against a hand-crafted request.
            if admin.subsidiary_scope and cert.subsidiary != admin.subsidiary_scope:
                missing += 1
                continue
            try:
                fn(session, deps.pki_path, serial, reason or "bulk action", admin.username)
                done += 1
            except KeyError:
                missing += 1
        if done:
            deps.regenerate_and_push_crl()

        verb = "suspended" if bulk_action == "suspend" else "revoked"
        kind = "warn" if bulk_action == "suspend" else "danger"
        msg = f"{done} certificate{'s' if done != 1 else ''} {verb}."
        if missing:
            msg += f" {missing} not found."
        dest = request.headers.get("referer", "/certs")
        return RedirectResponse(h.flash(dest, msg, kind), status_code=303)

    return router
