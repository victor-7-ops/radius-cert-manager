"""FastAPI app: router mounting, exception handlers, startup reconciliation.

Handoff §5.6: a catch-all exception handler returns a generic error plus
a correlation ID. Raw tracebacks must never reach a client.
"""

from __future__ import annotations

import contextvars
import json
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, scoped_session

import datetime
import urllib.request

from app import auth, cert_service, crl_health, crl_push, db, expiry_alerts, pki, reconcile
from app.config import Settings, load_settings
from app.db import init_db, make_engine, make_session_factory
from app.routes.certs import get_router as get_certs_router
from app.routes.health import get_router as get_health_router
from app.routes.web import get_router as get_web_router
from app.routes.web_auth import get_router as get_web_auth_router
from app.routes.bulk import get_router as get_bulk_router

BASE_DIR = Path(__file__).resolve().parent

logger = logging.getLogger("certmanager")

# Never log key material, .p12 bytes, or export passwords (§5.6) — this
# logger must only ever receive the fields explicitly passed below.


def _avatar_hue(name: str) -> int:
    """Deterministic 0-359 hue from a name, for a per-user avatar color
    that's stable across sessions without needing to store one."""
    return sum(ord(c) for c in (name or "?")) * 37 % 360


@dataclass
class RouteDeps:
    require_admin: callable
    require_super_admin: callable
    get_db_session: callable
    pki_path: Path
    db_path: Path
    inter_cert: object
    inter_key: object
    client_cert_days: int
    store_pending_bundle: callable
    take_pending_bundle: callable
    store_pending_password: callable
    take_pending_password: callable
    regenerate_and_push_crl: callable
    check_expiry_alerts: callable
    expiry_alert_days: int
    alert_webhook_url: str | None
    secret_key: str
    root_cert: object | None
    store_pending_preview: callable
    take_pending_preview: callable
    peek_pending_preview: callable
    store_pending_batch: callable
    take_pending_batch: callable
    peek_pending_batch: callable


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    engine = make_engine(str(settings.db_path))
    session_factory = make_session_factory(engine)
    init_db(engine)

    # Every route just called session_factory() straight, once per
    # deps.get_db_session() call, and nothing ever closed the result —
    # each request quietly leaked a connection back to nothing but GC
    # timing, and under any real concurrency (or a slow synchronous
    # regenerate_and_push_crl() holding one open through a CRL-push
    # retry/backoff) the pool exhausts. scoped_session ties one session
    # per request: the registry key is a ContextVar set once by the
    # middleware below, before FastAPI forks dependency/handler
    # resolution into separate threadpool calls — those calls each get
    # their own COPY of the context, but a copy still reads the value
    # set before the copy, so every get_db_session() call within one
    # request resolves to the same session, and request_scoped_db.remove()
    # after the response closes it and evicts it from the registry.
    _request_db_key: contextvars.ContextVar[object | None] = contextvars.ContextVar(
        "_request_db_key", default=None
    )
    request_scoped_db = scoped_session(session_factory, scopefunc=_request_db_key.get)

    inter_cert = pki.load_cert_pem(settings.pki_path / "intermediate.crt")
    inter_key = pki.load_key_pem(settings.pki_path / "private" / "intermediate.key")
    ca_chain_path = settings.pki_path / "ca-chain.pem"
    root_cert = pki.load_cert_pem(ca_chain_path) if ca_chain_path.exists() else None

    # First-run import, then reconciliation (handoff §5.8) — import runs
    # first so pre-existing certs are recorded rather than flagged.
    bootstrap_session = session_factory()
    issued_dir = settings.pki_path / "issued"
    issued_dir.mkdir(parents=True, exist_ok=True)
    reconcile.import_existing_certs(bootstrap_session, issued_dir)
    orphans = reconcile.reconcile_issued_dir(bootstrap_session, issued_dir)
    if orphans:
        logger.warning("startup reconciliation found orphaned certs: %s", orphans)
    bootstrap_session.close()

    require_admin, require_super_admin = auth.get_current_admin_factory(
        get_db_session=request_scoped_db,
        get_secret_key=lambda: settings.secret_key,
    )

    # One-time bundle store: serial -> Pkcs12Bundle, consumed on first read
    # (handoff §6.4 — a second request for the same bundle returns 410).
    pending_bundles: dict[str, object] = {}

    def store_pending_bundle(serial: str, bundle) -> None:
        if bundle is not None:
            pending_bundles[serial] = bundle

    def take_pending_bundle(serial: str):
        return pending_bundles.pop(serial, None)

    # Export password shown once on the delivery screen (handoff §6.4) —
    # never persisted, never logged, consumed alongside the bundle.
    pending_passwords: dict[str, str] = {}

    def store_pending_password(serial: str, password: str) -> None:
        pending_passwords[serial] = password

    def take_pending_password(serial: str):
        return pending_passwords.pop(serial, None)

    # Bulk issue (handoff §6.5): a preview token maps to the classified
    # valid-identifier list, consumed on confirm so a resubmitted preview
    # can't reissue the same batch twice. A batch entry (result + zip)
    # is kept until its ZIP is downloaded once (410 after).
    pending_previews: dict[str, list[str]] = {}
    pending_batches: dict[str, tuple[object, bytes]] = {}

    def store_pending_preview(token: str, identifiers: list[str]) -> None:
        pending_previews[token] = identifiers

    def take_pending_preview(token: str):
        return pending_previews.pop(token, None)

    def peek_pending_preview(token: str):
        # Non-consuming — the "fix a malformed row" flow mutates the
        # list in place (same object, no re-store needed) while the
        # batch is still under review; only /confirm consumes it.
        return pending_previews.get(token)

    def store_pending_batch(batch_id: str, result, zip_bytes: bytes) -> None:
        pending_batches[batch_id] = (result, zip_bytes)

    def peek_pending_batch(batch_id: str):
        return pending_batches.get(batch_id)

    def take_pending_batch(batch_id: str):
        return pending_batches.pop(batch_id, None)

    def _alert(message: str) -> None:
        logger.error("ALERT: %s", message)
        if not settings.alert_webhook_url:
            return
        try:
            # Slack incoming webhooks require a JSON body shaped
            # {"text": ...} — a plain-text POST is silently accepted
            # (200) but never posts anything, so this would have looked
            # "on standby and working" right up until someone actually
            # pointed it at Slack and nothing showed up.
            req = urllib.request.Request(
                settings.alert_webhook_url,
                data=json.dumps({"text": message}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            logger.exception("failed to deliver alert webhook")

    def check_expiry_alerts() -> list:
        session = request_scoped_db()
        return expiry_alerts.check_and_alert(session, _alert, warning_days=settings.expiry_alert_days)

    def regenerate_and_push_crl() -> None:
        session = request_scoped_db()
        pem = cert_service.regenerate_crl(
            session, settings.pki_path, inter_cert, inter_key, settings.crl_validity_days
        )
        next_update = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=settings.crl_validity_days
        )
        crl_health.record_generation(session, next_update)

        def _push():
            return crl_push.push_crl(
                settings.pki_path / "crl.pem",
                settings.radius_host,
                settings.radius_ssh_user,
                settings.radius_ssh_key,
            )

        crl_health.push_with_retry(session, _push, alert_fn=_alert)

    deps = RouteDeps(
        require_admin=require_admin,
        require_super_admin=require_super_admin,
        get_db_session=request_scoped_db,
        pki_path=settings.pki_path,
        db_path=settings.db_path,
        inter_cert=inter_cert,
        inter_key=inter_key,
        client_cert_days=settings.client_cert_days,
        store_pending_bundle=store_pending_bundle,
        take_pending_bundle=take_pending_bundle,
        store_pending_password=store_pending_password,
        take_pending_password=take_pending_password,
        regenerate_and_push_crl=regenerate_and_push_crl,
        check_expiry_alerts=check_expiry_alerts,
        expiry_alert_days=settings.expiry_alert_days,
        alert_webhook_url=settings.alert_webhook_url,
        secret_key=settings.secret_key,
        root_cert=root_cert,
        store_pending_preview=store_pending_preview,
        take_pending_preview=take_pending_preview,
        peek_pending_preview=peek_pending_preview,
        store_pending_batch=store_pending_batch,
        take_pending_batch=take_pending_batch,
        peek_pending_batch=peek_pending_batch,
    )

    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    templates.env.filters["avatar_hue"] = _avatar_hue
    templates.env.filters["subsidiary_color"] = db.subsidiary_color

    app = FastAPI(title="RADIUS Certificate Manager")

    @app.middleware("http")
    async def _scope_db_session_to_request(request: Request, call_next):
        token = _request_db_key.set(id(request))
        try:
            return await call_next(request)
        finally:
            request_scoped_db.remove()
            _request_db_key.reset(token)

    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
    app.include_router(get_certs_router(deps))
    app.include_router(get_health_router(deps))
    app.include_router(get_web_auth_router(deps, templates))
    app.include_router(get_bulk_router(deps, templates))
    app.include_router(get_web_router(deps, templates))
    app.state.regenerate_and_push_crl = regenerate_and_push_crl

    from fastapi import HTTPException
    from fastapi.responses import RedirectResponse

    ERROR_TITLES = {
        403: "You don't have access to this",
        404: "Not found",
        409: "Conflict",
        410: "No longer available",
        500: "Something went wrong",
    }

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        is_web_route = not request.url.path.startswith("/api")
        if exc.status_code == 401 and is_web_route:
            return RedirectResponse("/login", status_code=303)
        if exc.status_code == auth.PASSWORD_CHANGE_REQUIRED_STATUS and is_web_route:
            return RedirectResponse(auth.PASSWORD_CHANGE_PATH, status_code=303)
        if is_web_route and request.method == "GET":
            # A raw JSON error body is a "raw error text" failure mode for
            # a page a human is looking at (handoff §6.1) — render the
            # same designed error state instead.
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "status_code": exc.status_code,
                    "title": ERROR_TITLES.get(exc.status_code, "Error"),
                    "message": str(exc.detail),
                },
                status_code=exc.status_code,
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": "error", "message": str(exc.detail), "correlation_id": None}},
        )

    @app.exception_handler(Exception)
    async def catch_all(request: Request, exc: Exception):
        correlation_id = str(uuid.uuid4())
        logger.exception("unhandled error [correlation_id=%s]", correlation_id)
        if not request.url.path.startswith("/api") and request.method == "GET":
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "status_code": 500,
                    "title": ERROR_TITLES[500],
                    "message": f"An unexpected error occurred. Reference: {correlation_id}",
                },
                status_code=500,
            )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred.",
                    "correlation_id": correlation_id,
                }
            },
        )

    return app
