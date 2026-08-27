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

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select

from app import auth, bulk_service, cert_service, crl_health, db, rate_limit, reconcile
from app.validation import CN_RE, normalize_mac


def _flash(url: str, message: str, kind: str = "success") -> str:
    """Append a one-shot flash message to a redirect URL. base.html reads
    ?flash=/&flash_kind= on load, shows a toast, then strips the params
    from the address bar via history.replaceState — so a refresh doesn't
    re-show it and the URL doesn't stay ugly."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}flash={urllib.parse.quote(message)}&flash_kind={kind}"


def _qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return img.to_string(encoding="unicode")


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


def _ca_expiry_warnings(deps, now: datetime.datetime) -> list[str]:
    warnings = []
    for label, cert in (("Intermediate CA", deps.inter_cert), ("Root CA", deps.root_cert)):
        if cert is None:
            continue
        not_after = cert.not_valid_after_utc
        if not_after - now <= datetime.timedelta(days=180):
            warnings.append(f"{label} expires {not_after.date()}")
    return warnings


def _dir_size_bytes(path) -> int:
    total = 0
    if path.exists():
        for f in path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    return total


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _require_cert_scope(admin: db.Admin, cert: db.Certificate) -> None:
    """A subsidiary-scoped admin can only act on certs for their own
    company. Unscoped admins (subsidiary_scope is None/blank) are
    unrestricted, same as before this feature existed."""
    if admin.subsidiary_scope and cert.subsidiary != admin.subsidiary_scope:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not permitted for this subsidiary")


def _require_unscoped(admin: db.Admin, detail: str) -> None:
    if admin.subsidiary_scope:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)


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

        cert_stmt = select(db.Certificate)
        if admin.subsidiary_scope:
            cert_stmt = cert_stmt.where(db.Certificate.subsidiary == admin.subsidiary_scope)
        rows = session.scalars(cert_stmt).all()
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

        orphans = reconcile.reconcile_issued_dir(session, deps.pki_path / "issued") if not admin.subsidiary_scope else []

        if admin.subsidiary_scope:
            # AuditLog has no subsidiary column, so filter by matching
            # target against this admin's own certs — that also drops
            # admin-management entries (their target is a username, which
            # won't match any cn), which a scoped admin shouldn't see anyway.
            own_cns = {c.cn for c in rows}
            recent = [
                a for a in session.scalars(
                    select(db.AuditLog).order_by(db.AuditLog.timestamp.desc()).limit(200)
                ).all()
                if a.target in own_cns
            ][:10]
        else:
            recent = session.scalars(
                select(db.AuditLog).order_by(db.AuditLog.timestamp.desc()).limit(10)
            ).all()

        health = crl_health.get_health(session)
        ca_warnings = _ca_expiry_warnings(deps, now)

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

    def _cert_filter_stmt(q, status, employee, subsidiary, admin=None):
        """Shared by the list page and the CSV export so the two can
        never silently drift apart on what a filter means."""
        stmt = select(db.Certificate)
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
        stmt = _cert_filter_stmt(q, status, employee, subsidiary, admin).offset((page - 1) * page_size).limit(page_size)
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
                c.cn, c.serial, _effective_status(c), c.issued_at.isoformat(), c.expires_at.isoformat(),
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
                select(db.Certificate).where(db.Certificate.status == db.CertStatus.active, or_(*conds))
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
            _require_cert_scope(admin, cert)

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
                "qr_svg": _qr_svg(qr_url),
                "qr_expires_minutes": auth.BUNDLE_QR_TOKEN_MAX_AGE_SECONDS // 60,
                **_crl_banner_context(session),
            },
        )

    @router.get("/certs/{serial}/bundle/qr")
    def download_bundle_via_qr(request: Request, serial: str, token: str = ""):
        from fastapi import Response

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
        from fastapi import Response

        if rate_limit.is_rate_limited(f"bundle:{admin.id}", max_requests=30, window_seconds=60):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts — wait a minute and try again.")
        if admin.subsidiary_scope:
            session = deps.get_db_session()
            cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
            if cert is not None:
                _require_cert_scope(admin, cert)
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
        _require_cert_scope(admin, cert)

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

    def _load_cert_or_404_in_scope(session, admin: db.Admin, serial: str) -> db.Certificate:
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        _require_cert_scope(admin, cert)
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
        return RedirectResponse(_flash(dest, f"{cert.cn} suspended.", "warn"), status_code=303)

    @router.post("/certs/{serial}/unsuspend")
    def unsuspend(request: Request, serial: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        _load_cert_or_404_in_scope(session, admin, serial)
        try:
            cert = cert_service.unsuspend(session, deps.pki_path, serial, admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return RedirectResponse(_flash(f"/certs/{serial}", f"{cert.cn} unsuspended.", "success"), status_code=303)

    @router.post("/certs/{serial}/revoke")
    def revoke(request: Request, serial: str, reason: str = "", admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        _load_cert_or_404_in_scope(session, admin, serial)
        try:
            cert = cert_service.revoke(session, deps.pki_path, serial, reason or "not specified", admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return RedirectResponse(_flash(f"/certs/{serial}", f"{cert.cn} revoked.", "danger"), status_code=303)

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
        return RedirectResponse(_flash(dest, msg, kind), status_code=303)

    # --- System health (Super Admin only) ---

    @router.get("/health")
    def health_page(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        import shutil

        session = deps.get_db_session()
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = crl_health.get_health(session)

        status_counts = {"active": 0, "suspended": 0, "revoked": 0, "expired": 0}
        for c in session.scalars(select(db.Certificate)).all():
            status_counts[_effective_status(c)] = status_counts.get(_effective_status(c), 0) + 1

        db_size = deps.db_path.stat().st_size if deps.db_path.exists() else 0
        pki_size = _dir_size_bytes(deps.pki_path)
        disk = shutil.disk_usage(deps.pki_path if deps.pki_path.exists() else deps.pki_path.parent)

        active_sessions = session.scalar(
            select(func.count()).select_from(db.AdminSession).where(db.AdminSession.revoked_at.is_(None))
        )
        active_admins = session.scalar(
            select(func.count()).select_from(db.Admin).where(db.Admin.is_active == True)  # noqa: E712
        )

        orphans = reconcile.reconcile_issued_dir(session, deps.pki_path / "issued")

        # Opportunistic, not scheduled — see app/expiry_alerts.py. Only
        # ever alerts about certs that just crossed the window since the
        # last time this page loaded, so reloading doesn't re-spam.
        newly_alerted = deps.check_expiry_alerts()

        return templates.TemplateResponse(
            request,
            "health.html",
            {
                "admin": admin,
                "crl": crl,
                "status_counts": status_counts,
                "cert_total": sum(status_counts.values()),
                "db_size": _human_bytes(db_size),
                "pki_size": _human_bytes(pki_size),
                "disk_free": _human_bytes(disk.free),
                "disk_total": _human_bytes(disk.total),
                "disk_used_pct": round(100 * (disk.total - disk.free) / disk.total, 1) if disk.total else 0,
                "ca_warnings": _ca_expiry_warnings(deps, now),
                "active_sessions": active_sessions,
                "active_admins": active_admins,
                "orphans": orphans,
                "newly_alerted": [{"cn": c.cn, "expires_at": c.expires_at.date()} for c in newly_alerted],
                "expiry_alert_days": deps.expiry_alert_days,
                "slack_configured": bool(deps.alert_webhook_url),
                **_crl_banner_context(session),
            },
        )

    # --- Change your own password (self-service; also where
    # must_change_password redirects, see auth.require_admin) ---

    @router.get(auth.PASSWORD_CHANGE_PATH)
    def change_password_form(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request,
            "change_password.html",
            {
                "admin": admin,
                "forced": admin.must_change_password,
                "min_length": auth.MIN_PASSWORD_LENGTH,
                **_crl_banner_context(session),
            },
        )

    @router.post(auth.PASSWORD_CHANGE_PATH)
    def change_password_submit(
        request: Request,
        current_password: str = Form(...),
        new_password: str = Form(...),
        confirm_password: str = Form(...),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        error = None
        if not auth.verify_password(current_password, admin.password_hash):
            error = "Current password is incorrect."
        elif new_password != confirm_password:
            error = "New password and confirmation don't match."
        elif len(new_password) < auth.MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {auth.MIN_PASSWORD_LENGTH} characters."
        elif new_password == current_password:
            error = "New password must be different from your current password."

        if error:
            return templates.TemplateResponse(
                request,
                "change_password.html",
                {
                    "admin": admin,
                    "forced": admin.must_change_password,
                    "min_length": auth.MIN_PASSWORD_LENGTH,
                    "error": error,
                    **_crl_banner_context(session),
                },
                status_code=400,
            )

        admin.password_hash = auth.hash_password(new_password)
        admin.must_change_password = False
        db.audit(session, actor=admin.username, action="change_password", target=admin.username)
        session.commit()
        return RedirectResponse(_flash("/dashboard", "Password changed.", "success"), status_code=303)

    # --- Your sessions (any admin, own sessions only) ---

    @router.get("/account/sessions")
    def account_sessions(
        request: Request,
        cm_session: str | None = Cookie(default=None),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        current_id = None
        if cm_session is not None:
            data = auth.decode_session_cookie(deps.secret_key, cm_session)
            if data is not None:
                current_id = data.session_id
        rows = session.scalars(
            select(db.AdminSession)
            .where(db.AdminSession.admin_id == admin.id, db.AdminSession.revoked_at.is_(None))
            .order_by(db.AdminSession.last_seen_at.desc())
        ).all()
        return templates.TemplateResponse(
            request,
            "account_sessions.html",
            {
                "admin": admin,
                "sessions": [
                    {
                        "id": s.id,
                        "is_current": s.id == current_id,
                        "user_agent": s.user_agent,
                        "ip_address": s.ip_address,
                        "created_at": s.created_at,
                        "last_seen_at": s.last_seen_at,
                    }
                    for s in rows
                ],
                **_crl_banner_context(session),
            },
        )

    @router.post("/account/sessions/{session_id}/revoke")
    def account_session_revoke(
        request: Request,
        session_id: str,
        cm_session: str | None = Cookie(default=None),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        record = session.get(db.AdminSession, session_id)
        if record is None or record.admin_id != admin.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        current_id = None
        if cm_session is not None:
            data = auth.decode_session_cookie(deps.secret_key, cm_session)
            if data is not None:
                current_id = data.session_id
        if record.id == current_id:
            # Ending your own current session isn't "revoke a device",
            # it's "log out" — send them through the real logout path so
            # the cookie gets cleared too, not just the DB row.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "use logout to end your current session")
        auth.revoke_admin_session(session, record)
        return RedirectResponse(_flash("/account/sessions", "Session ended.", "warn"), status_code=303)

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
            items.append({
                "id": a.id, "username": a.username, "role": a.role.value, "is_active": a.is_active,
                "is_last_super_admin": is_last, "subsidiary_scope": a.subsidiary_scope,
            })
        return templates.TemplateResponse(
            request,
            "admin_list.html",
            {"admin": admin, "admins": items, "only_one_super_admin": super_count <= 1, **_crl_banner_context(session)},
        )

    @router.get("/admins/new-form")
    def admin_new_form(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        return templates.TemplateResponse(request, "admin_new_form.html", {"subsidiaries": db.SUBSIDIARIES})

    @router.post("/admins")
    def admin_create(
        request: Request,
        username: str = Form(...),
        role: str = Form(...),
        subsidiary_scope: str = Form(""),
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
            subsidiary_scope=subsidiary_scope.strip() or None,
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
        date_from: str | None = None,
        date_to: str | None = None,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        # AuditLog has no subsidiary column, so there's no clean way to
        # scope this view — keep it unscoped-admin only rather than
        # showing a scoped admin other subsidiaries' activity.
        _require_unscoped(admin, "activity log isn't available to a subsidiary-scoped admin")
        session = deps.get_db_session()
        LIMIT = 200
        stmt = select(db.AuditLog).order_by(db.AuditLog.timestamp.desc())
        if actor:
            stmt = stmt.where(db.AuditLog.actor.contains(actor))
        if action:
            stmt = stmt.where(db.AuditLog.action == action)
        if date_from:
            try:
                stmt = stmt.where(db.AuditLog.timestamp >= datetime.datetime.fromisoformat(date_from))
            except ValueError:
                date_from = None
        if date_to:
            try:
                stmt = stmt.where(
                    db.AuditLog.timestamp < datetime.datetime.fromisoformat(date_to) + datetime.timedelta(days=1)
                )
            except ValueError:
                date_to = None
        rows = session.scalars(stmt.limit(LIMIT + 1)).all()
        truncated = len(rows) > LIMIT
        rows = rows[:LIMIT]
        known_actions = sorted(a for (a,) in session.execute(select(db.AuditLog.action).distinct()))
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
                "date_from": date_from,
                "date_to": date_to,
                "known_actions": known_actions,
                "truncated": truncated,
                "result_limit": LIMIT,
                **_crl_banner_context(session),
            },
        )

    @router.get("/")
    def root():
        return RedirectResponse("/dashboard", status_code=303)

    return router
