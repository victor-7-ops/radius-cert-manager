"""Server-rendered UI routes (Jinja2 + HTMX) — handoff §6.

Suspend is available to Admin; unsuspend and revoke require Super Admin
(handoff §7). Buttons the current role can't use are absent from the
template context entirely, not rendered-and-disabled.
"""

from __future__ import annotations

import csv
import datetime
import io
import urllib.parse
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app import auth, cert_service, crl_health, db, reconcile
from app.validation import CN_RE, normalize_mac


def _flash(url: str, message: str, kind: str = "success") -> str:
    """Append a one-shot flash message to a redirect URL. base.html reads
    ?flash=/&flash_kind= on load, shows a toast, then strips the params
    from the address bar via history.replaceState — so a refresh doesn't
    re-show it and the URL doesn't stay ugly."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}flash={urllib.parse.quote(message)}&flash_kind={kind}"


def _relative_expiry(expires_at: datetime.datetime) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    delta = expires_at - now
    days = delta.days
    if days < 0:
        return "expired"
    if days == 0:
        return "today"
    return f"in {days} days"


def _effective_status(cert: db.Certificate) -> str:
    if cert.status == db.CertStatus.active and cert.is_expired():
        return "expired"
    return cert.status.value if hasattr(cert.status, "value") else cert.status


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web"])

    _crl_banner_context = crl_health.banner_context

    @router.get("/login")
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {})

    @router.get("/dashboard")
    def dashboard(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        now = datetime.datetime.now(datetime.timezone.utc)
        thirty_days = now + datetime.timedelta(days=30)

        rows = session.scalars(select(db.Certificate)).all()
        counts = {"active": 0, "expiring_soon": 0, "suspended": 0, "revoked": 0, "expired": 0}
        expiring = []
        for c in rows:
            eff = _effective_status(c)
            if eff == "active":
                counts["active"] += 1
                exp = c.expires_at.replace(tzinfo=datetime.timezone.utc) if c.expires_at.tzinfo is None else c.expires_at
                if exp <= thirty_days:
                    counts["expiring_soon"] += 1
                    expiring.append(c)
            elif eff == "expired":
                counts["expired"] += 1
            elif c.status == db.CertStatus.suspended:
                counts["suspended"] += 1
            elif c.status == db.CertStatus.revoked:
                counts["revoked"] += 1

        # Donut chart segments (handoff has no chart requirement — this is
        # a glance-value add). Mutually exclusive buckets only; expiring_soon
        # is a subset of active, shown separately in "Attention needed".
        donut_buckets = [
            ("active", counts["active"], "#16a34a"),
            ("suspended", counts["suspended"], "#d97706"),
            ("revoked", counts["revoked"], "#dc2626"),
            ("expired", counts["expired"], "#94a3b8"),
        ]
        donut_total = sum(n for _, n, _ in donut_buckets)
        donut_segments = []
        cursor = 0.0
        if donut_total:
            for label, n, color in donut_buckets:
                if n == 0:
                    continue
                start = cursor
                cursor += 360 * n / donut_total
                donut_segments.append({"label": label, "count": n, "color": color, "start": round(start, 1), "end": round(cursor, 1)})

        # By-company breakdown (handoff has no requirement for this — a
        # glance-value add for tracking subsidiaries). Every cert counts
        # once here regardless of status, since this answers "how many
        # devices does each company have on file", not "how many are
        # currently valid" — that's what the status donut above is for.
        company_totals: dict[str, int] = {}
        for c in rows:
            key = c.subsidiary or "Unassigned"
            company_totals[key] = company_totals.get(key, 0) + 1
        company_breakdown = [
            {
                "name": name,
                "count": n,
                "color": db.subsidiary_color(None if name == "Unassigned" else name),
                "pct": round(100 * n / len(rows), 1) if rows else 0,
            }
            for name, n in sorted(company_totals.items(), key=lambda kv: kv[1], reverse=True)
        ]

        # Same breakdown, as conic-gradient segments for the inner ring of
        # the fleet-status donut — otherwise an all-one-status fleet (the
        # common case early on) renders as a flat, boring single-color ring.
        company_segments = []
        cursor = 0.0
        for c in company_breakdown:
            start = cursor
            cursor += 360 * c["count"] / len(rows) if rows else 0
            company_segments.append({**c, "start": round(start, 1), "end": round(cursor, 1)})

        # Issuance-over-time: last 6 calendar months, oldest first. Built
        # from the same `rows` fetch above rather than a second query —
        # this dashboard is already all-certs-in-memory, no need to hit
        # the DB again for one more aggregate over the same data.
        month_counts: dict[str, int] = {}
        month_labels: list[tuple[str, str]] = []
        cursor_month = now.replace(day=1)
        for _ in range(6):
            key = cursor_month.strftime("%Y-%m")
            month_labels.append((key, cursor_month.strftime("%b")))
            month_counts[key] = 0
            cursor_month = (cursor_month - datetime.timedelta(days=1)).replace(day=1)
        month_labels.reverse()
        for c in rows:
            issued_at = c.issued_at.replace(tzinfo=datetime.timezone.utc) if c.issued_at.tzinfo is None else c.issued_at
            key = issued_at.strftime("%Y-%m")
            if key in month_counts:
                month_counts[key] += 1
        issuance_max = max(month_counts.values()) if month_counts else 0
        issuance_trend = [
            {
                "label": label,
                "count": month_counts[key],
                "pct": round(100 * month_counts[key] / issuance_max) if issuance_max else 0,
            }
            for key, label in month_labels
        ]

        orphans = reconcile.reconcile_issued_dir(session, deps.pki_path / "issued")

        recent = session.scalars(
            select(db.AuditLog).order_by(db.AuditLog.timestamp.desc()).limit(10)
        ).all()

        health = crl_health.get_health(session)

        ca_warnings = []
        for label, cert in (("Intermediate CA", deps.inter_cert), ("Root CA", deps.root_cert)):
            if cert is None:
                continue
            not_after = cert.not_valid_after_utc
            if not_after - now <= datetime.timedelta(days=180):
                ca_warnings.append(f"{label} expires {not_after.date()}")

        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "admin": admin,
                "counts": counts,
                "donut_segments": donut_segments,
                "donut_total": donut_total,
                "company_breakdown": company_breakdown,
                "company_segments": company_segments,
                "company_total": len(rows),
                "issuance_trend": issuance_trend,
                "expiring": [{"cn": c.cn, "serial": c.serial, "expires_at": c.expires_at.date()} for c in expiring],
                "orphans": orphans,
                "recent_activity": [
                    {"actor": a.actor, "action": a.action, "target": a.target, "timestamp": a.timestamp}
                    for a in recent
                ],
                "crl_health": {
                    "last_generated_at": health.last_generated_at,
                    "last_pushed_at": health.last_pushed_at,
                    "last_push_ok": health.last_push_ok,
                    "next_update": health.next_update,
                },
                "ca_expiry_warnings": ca_warnings,
                **_crl_banner_context(session),
            },
        )

    def _cert_filter_stmt(q, status, employee, subsidiary):
        """Shared by the list page and the CSV export so the two can
        never silently drift apart on what a filter means."""
        stmt = select(db.Certificate)
        if q:
            stmt = stmt.where(
                db.Certificate.cn.contains(q) | db.Certificate.employee_name.contains(q)
            )
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
            # (_effective_status), so the Active filter must exclude it —
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
        stmt = _cert_filter_stmt(q, status, employee, subsidiary).offset((page - 1) * page_size).limit(page_size)
        rows = session.scalars(stmt).all()

        items = [
            {
                "cn": c.cn,
                "serial": c.serial,
                "status": _effective_status(c),
                "issued_at": c.issued_at.date(),
                "expires_relative": _relative_expiry(c.expires_at),
                "issued_by": c.issued_by,
                "employee_name": c.employee_name,
                "device_type": c.device_type,
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
                "subsidiary_filter": subsidiary,
                "subsidiaries": db.SUBSIDIARIES,
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
        # Whatever filter the admin currently has applied on the list
        # page — the export is "what I'm looking at", not "everything".
        session = deps.get_db_session()
        rows = session.scalars(_cert_filter_stmt(q, status, employee, subsidiary)).all()

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "cn", "serial", "status", "issued_at", "expires_at", "issued_by",
            "employee_name", "device_type", "device_mac", "device_serial", "subsidiary",
        ])
        for c in rows:
            writer.writerow([
                c.cn, c.serial, _effective_status(c), c.issued_at.isoformat(), c.expires_at.isoformat(),
                c.issued_by, c.employee_name or "", c.device_type or "", c.device_mac or "",
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
                "subsidiaries": db.SUBSIDIARIES,
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
        device_mac: str = Form(""),
        device_serial: str = Form(""),
        subsidiary: str = Form(""),
        request_id: str = Form(...),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        form_context = {
            "admin": admin,
            "request_id": request_id,
            "device_types": db.DEVICE_TYPES,
            "subsidiaries": db.SUBSIDIARIES,
            "form": {
                "cn": cn,
                "employee_name": employee_name,
                "device_type": device_type,
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
        return templates.TemplateResponse(
            request,
            "delivery.html",
            {"admin": admin, "cn": cert.cn, "serial": serial, "export_password": password, **_crl_banner_context(session)},
        )

    @router.get("/certs/{serial}/bundle")
    def download_bundle(serial: str, admin: db.Admin = Depends(deps.require_admin)):
        from fastapi import Response

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
                    "status": _effective_status(cert),
                    "issued_at": cert.issued_at,
                    "expires_at": cert.expires_at,
                    "issued_by": cert.issued_by,
                    "note": cert.note,
                    "employee_name": cert.employee_name,
                    "device_type": cert.device_type,
                    "device_mac": cert.device_mac,
                    "device_serial": cert.device_serial,
                    "subsidiary": cert.subsidiary,
                    "supersedes_cn": supersedes.cn if supersedes else None,
                    "supersedes_serial": supersedes.serial if supersedes else None,
                    "superseded_by_cn": superseded_by.cn if superseded_by else None,
                    "superseded_by_serial": superseded_by.serial if superseded_by else None,
                },
                "history": [
                    {"action": h.action, "actor": h.actor, "detail": h.detail, "timestamp": h.timestamp}
                    for h in history_rows
                ],
                "can_suspend": True,
                "can_unsuspend": is_super,
                "can_revoke": is_super,
                "other_device_count": other_device_count,
                **_crl_banner_context(session),
            },
        )

    @router.post("/certs/{serial}/reissue")
    def reissue(request: Request, serial: str, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
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
        try:
            cert = cert_service.suspend(session, deps.pki_path, serial, reason or "not specified", admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        dest = request.headers.get("referer", "/certs")
        return RedirectResponse(_flash(dest, f"{cert.cn} suspended.", "warn"), status_code=303)

    @router.post("/certs/{serial}/unsuspend")
    def unsuspend(request: Request, serial: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        try:
            cert = cert_service.unsuspend(session, deps.pki_path, serial, admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return RedirectResponse(_flash(f"/certs/{serial}", f"{cert.cn} unsuspended.", "success"), status_code=303)

    @router.post("/certs/{serial}/revoke")
    def revoke(request: Request, serial: str, reason: str = "", admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        try:
            cert = cert_service.revoke(session, deps.pki_path, serial, reason or "not specified", admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return RedirectResponse(_flash(f"/certs/{serial}", f"{cert.cn} revoked.", "danger"), status_code=303)

    # --- Admin management (Super Admin only) ---

    def _active_super_admin_count(session) -> int:
        return session.scalar(
            select(func.count()).select_from(db.Admin).where(
                db.Admin.role == db.AdminRole.super_admin, db.Admin.is_active == True  # noqa: E712
            )
        )

    @router.get("/admins")
    def admin_list(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        rows = session.scalars(select(db.Admin)).all()
        super_count = _active_super_admin_count(session)
        items = []
        for a in rows:
            is_last = a.role == db.AdminRole.super_admin and a.is_active and super_count == 1
            items.append({"id": a.id, "username": a.username, "role": a.role.value, "is_active": a.is_active, "is_last_super_admin": is_last})
        return templates.TemplateResponse(
            request,
            "admin_list.html",
            {"admin": admin, "admins": items, "only_one_super_admin": super_count <= 1, **_crl_banner_context(session)},
        )

    @router.get("/admins/new-form")
    def admin_new_form(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        return templates.TemplateResponse(request, "admin_new_form.html", {})

    @router.post("/admins")
    def admin_create(
        request: Request,
        username: str = Form(...),
        role: str = Form(...),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        import secrets

        temp_password = secrets.token_urlsafe(12)
        new_admin = db.Admin(
            username=username,
            password_hash=auth.hash_password(temp_password),
            role=db.AdminRole(role),
            must_change_password=True,
            created_by=admin.username,
        )
        session.add(new_admin)
        db.audit(session, actor=admin.username, action="create_admin", target=username)
        session.commit()
        return templates.TemplateResponse(request, "admin_created.html", {"username": username, "temp_password": temp_password})

    @router.post("/admins/{admin_id}/deactivate")
    def admin_deactivate(request: Request, admin_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        target = session.get(db.Admin, admin_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        if target.role == db.AdminRole.super_admin and _active_super_admin_count(session) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot deactivate the last active Super Admin")
        target.is_active = False
        auth.bump_token_version(session, target)
        db.audit(session, actor=admin.username, action="deactivate_admin", target=target.username)
        session.commit()
        return RedirectResponse(_flash("/admins", f"{target.username} deactivated.", "warn"), status_code=303)

    @router.post("/admins/{admin_id}/reset-password")
    def admin_reset_password(request: Request, admin_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        target = session.get(db.Admin, admin_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        import secrets

        temp_password = secrets.token_urlsafe(12)
        target.password_hash = auth.hash_password(temp_password)
        target.must_change_password = True
        auth.bump_token_version(session, target)
        db.audit(session, actor=admin.username, action="reset_password", target=target.username)
        session.commit()
        return templates.TemplateResponse(
            request, "admin_created.html", {"username": target.username, "temp_password": temp_password}
        )

    @router.post("/admins/{admin_id}/force-logout")
    def admin_force_logout(request: Request, admin_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        target = session.get(db.Admin, admin_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        auth.bump_token_version(session, target)
        db.audit(session, actor=admin.username, action="force_logout", target=target.username)
        session.commit()
        return RedirectResponse(_flash("/admins", f"{target.username} logged out everywhere.", "success"), status_code=303)

    @router.get("/activity")
    def activity(
        request: Request,
        actor: str | None = None,
        action: str | None = None,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        stmt = select(db.AuditLog).order_by(db.AuditLog.timestamp.desc())
        if actor:
            stmt = stmt.where(db.AuditLog.actor.contains(actor))
        if action:
            stmt = stmt.where(db.AuditLog.action.contains(action))
        rows = session.scalars(stmt.limit(200)).all()
        return templates.TemplateResponse(
            request,
            "activity_log.html",
            {
                "admin": admin,
                "entries": [
                    {"timestamp": e.timestamp, "actor": e.actor, "action": e.action, "target": e.target, "detail": e.detail}
                    for e in rows
                ],
                "actor": actor,
                "action_filter": action,
                **_crl_banner_context(session),
            },
        )

    @router.get("/")
    def root():
        return RedirectResponse("/dashboard", status_code=303)

    return router
