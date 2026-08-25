"""FastAPI app: router mounting, exception handlers, startup reconciliation.

Handoff §5.6: a catch-all exception handler returns a generic error plus
a correlation ID. Raw tracebacks must never reach a client.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

import datetime
import urllib.request

from app import auth, cert_service, crl_health, crl_push, pki, reconcile
from app.config import Settings, load_settings
from app.db import init_db, make_engine, make_session_factory
from app.routes.certs import get_router as get_certs_router
from app.routes.health import get_router as get_health_router

logger = logging.getLogger("certmanager")

# Never log key material, .p12 bytes, or export passwords (§5.6) — this
# logger must only ever receive the fields explicitly passed below.


@dataclass
class RouteDeps:
    require_admin: callable
    require_super_admin: callable
    get_db_session: callable
    pki_path: Path
    inter_cert: object
    inter_key: object
    client_cert_days: int
    store_pending_bundle: callable
    take_pending_bundle: callable
    regenerate_and_push_crl: callable


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()

    engine = make_engine(str(settings.db_path))
    session_factory = make_session_factory(engine)
    init_db(engine)

    inter_cert = pki.load_cert_pem(settings.pki_path / "intermediate.crt")
    inter_key = pki.load_key_pem(settings.pki_path / "private" / "intermediate.key")

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
        get_db_session=lambda: session_factory(),
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

    def _alert(message: str) -> None:
        logger.error("ALERT: %s", message)
        if not settings.alert_webhook_url:
            return
        try:
            req = urllib.request.Request(
                settings.alert_webhook_url,
                data=message.encode(),
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception:
            logger.exception("failed to deliver alert webhook")

    def regenerate_and_push_crl() -> None:
        session = session_factory()
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
        get_db_session=lambda: session_factory(),
        pki_path=settings.pki_path,
        inter_cert=inter_cert,
        inter_key=inter_key,
        client_cert_days=settings.client_cert_days,
        store_pending_bundle=store_pending_bundle,
        take_pending_bundle=take_pending_bundle,
        regenerate_and_push_crl=regenerate_and_push_crl,
    )

    app = FastAPI(title="RADIUS Certificate Manager")
    app.include_router(get_certs_router(deps))
    app.include_router(get_health_router(deps))
    app.state.regenerate_and_push_crl = regenerate_and_push_crl

    @app.exception_handler(Exception)
    async def catch_all(request: Request, exc: Exception):
        correlation_id = str(uuid.uuid4())
        logger.exception("unhandled error [correlation_id=%s]", correlation_id)
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
