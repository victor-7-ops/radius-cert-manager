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

from app import auth, bulk_service, cert_service, crl_health, db, rate_limit
from app.routes import web_helpers as h
from app.validation import CN_RE, normalize_mac


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-certs"])

    _crl_banner_context = crl_health.banner_context

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
            stmt = stmt.where(db.Certificate.employee_name == employee)
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
                "subsidiaries": [admin.subsidiary_scope] if admin.subsidiary_scope else db.SUBSIDIARIES,
                **_crl_banner_context(session),
            },
        )

    @router.get("/certs/export.csv")
    def cert_export(
        q: str | None = None,
        status: str | None = None,
        employee: str | None = None,
        subsidiary: str | None = None,
        admin: db.Admin = Depends(deps.require_admin),
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
            select(db.Certificate).where(db.Certificate.cn == cn, db.Certificate.status == db.CertStatus.active)
        )
        if existing is not None:
            return HTMLResponse(f'<span class="text-red-600">An active certificate for "{cn}" already exists.</span>')
        return HTMLResponse('<span class="text-green-600">Available.</span>')

    @router.get("/certs/issue")
    def issue_form(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request,
            "issue.html",
            {
                "admin": admin,
                "request_id": str(uuid.uuid4()),
                "device_types": db.DEVICE_TYPES,
                "subsidiaries": [admin.subsidiary_scope] if admin.subsidiary_scope else db.SUBSIDIARIES,
                "form": {"subsidiary": admin.subsidiary_scope} if admin.subsidiary_scope else None,
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
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        if admin.subsidiary_scope:
            # Scoped admin: the subsidiary isn't a free-text choice, it's
            # who they are. Ignore whatever the form sent (hidden/disabled
            # client-side, but never trust that alone) and force it.
            subsidiary = admin.subsidiary_scope
        form_context = {
            "admin": admin,
            "request_id": request_id,
            "device_types": db.DEVICE_TYPES,
            "subsidiaries": [admin.subsidiary_scope] if admin.subsidiary_scope else db.SUBSIDIARIES,
            "form": {
                "cn": cn,
                "employee_name": employee_name,
                "device_type": device_type,
                "device_model": device_model,
                "device_mac": device_mac,
                "device_serial": device_serial,
                "subsidiary": subsidiary,
                "note": note,
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
                    subsidiary=subsidiary.strip() or None,
                ),
            )
        except cert_service.CNConflictError:
            return templates.TemplateResponse(
                request,
                "issue.html",
                {**form_context, "error": f'An active certificate for "{cn}" already exists.'},
                status_code=409,
            )
        if result.bundle is None:
            return RedirectResponse(f"/certs/{result.certificate.serial}", status_code=303)
        deps.store_pending_bundle(result.certificate.serial, result.bundle)
        deps.store_pending_password(result.certificate.serial, result.bundle.password)
        return RedirectResponse(f"/certs/{result.certificate.serial}/delivery", status_code=303)

    @router.get("/certs/{serial}/delivery")
    def delivery(request: Request, serial: str, admin: db.Admin = Depends(deps.require_admin)):
        password = deps.take_pending_password(serial)
        if password is None:
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
        qr_url = str(request.base_url).rstrip("/") + f"/certs/{serial}/bundle/qr?token={qr_token}"

        return templates.TemplateResponse(
            request,
            "delivery.html",
            {
                "admin": admin,
                "cn": cert.cn,
                "serial": serial,
                "export_password": password,
                "qr_svg": h.qr_svg(qr_url),
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

    @router.get("/certs/{serial}/bundle")
    def download_bundle(serial: str, admin: db.Admin = Depends(deps.require_admin)):
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

    @router.get("/certs/{serial}")
    def cert_detail(request: Request, serial: str, admin: db.Admin = Depends(deps.require_admin)):
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
        if cert.employee_name:
            other_device_count = session.scalar(
                select(func.count()).select_from(db.Certificate).where(
                    db.Certificate.employee_name == cert.employee_name,
                    db.Certificate.id != cert.id,
                )
            )

        is_super = admin.role == db.AdminRole.super_admin
        return templates.TemplateResponse(
            request,
            "cert_detail.html",
            {
                "admin": admin,
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
    def reissue(request: Request, serial: str, admin: db.Admin = Depends(deps.require_admin)):
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
        deps.store_pending_bundle(result.certificate.serial, result.bundle)
        deps.store_pending_password(result.certificate.serial, result.bundle.password)
        return RedirectResponse(f"/certs/{result.certificate.serial}/delivery", status_code=303)

    @router.post("/certs/{serial}/suspend")
    def suspend(request: Request, serial: str, reason: str = "", admin: db.Admin = Depends(deps.require_admin)):
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
        admin: db.Admin = Depends(deps.require_admin),
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
