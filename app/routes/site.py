"""Agent-facing site check-in/pull API (HANDOFF-FLEET.md §4.3). Token-
authenticated via app.site_auth.require_site — never the admin session
cookie, and not reachable by one either, since this router has no
Depends(deps.require_admin) anywhere in it."""

from __future__ import annotations

import datetime
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from app import cert_service, db, rate_limit


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


CHECKIN_RATE_LIMIT = (30, 60.0)  # max requests, window seconds
CRL_RATE_LIMIT = (30, 60.0)
RENEW_RATE_LIMIT = (10, 60.0)


def _enforce_rate_limit(site: db.Site, bucket: str, limit: tuple[int, float]) -> None:
    max_requests, window = limit
    if rate_limit.is_rate_limited(f"site:{bucket}:{site.id}", max_requests, window):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests")


def get_router(deps) -> APIRouter:
    router = APIRouter(prefix="/api/site", tags=["site"])

    @router.post("/checkin")
    def checkin(
        payload: dict,
        site: db.Site = Depends(deps.require_site),
    ):
        _enforce_rate_limit(site, "checkin", CHECKIN_RATE_LIMIT)
        session = deps.get_db_session()

        agent_version = payload.get("agent_version")
        freeradius_ok = payload.get("freeradius_ok")
        reported_crl_sha256 = payload.get("crl_sha256")
        server_cert_serial = payload.get("server_cert_serial")

        site.last_seen_at = _now()
        site.agent_version = agent_version
        site.last_reported_freeradius_ok = freeradius_ok
        site.last_reported_crl_sha256 = reported_crl_sha256

        crl_path = deps.pki_path / "crl.pem"
        current_crl_sha256 = (
            hashlib.sha256(crl_path.read_bytes()).hexdigest() if crl_path.exists() else None
        )
        newer_crl_available = (
            current_crl_sha256 is not None and current_crl_sha256 != reported_crl_sha256
        )

        renewal_due = False
        if server_cert_serial is not None:
            cert = session.scalar(
                select(db.Certificate).where(db.Certificate.serial == str(server_cert_serial))
            )
            if cert is not None:
                renewal_due = cert_service.renewal_due(cert)

        db.audit(
            session, actor=f"site:{site.radius_cn}", action="checkin", target=site.radius_cn,
            detail=f"freeradius_ok={freeradius_ok} agent_version={agent_version}",
        )
        session.commit()

        return {
            "newer_crl_available": newer_crl_available,
            "renewal_due": renewal_due,
            "next_checkin_interval_seconds": site.checkin_interval_seconds,
        }

    @router.get("/crl")
    def get_crl(
        request: Request,
        site: db.Site = Depends(deps.require_site),
    ):
        _enforce_rate_limit(site, "crl", CRL_RATE_LIMIT)
        session = deps.get_db_session()
        crl_path = deps.pki_path / "crl.pem"
        if not crl_path.exists():
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No CRL generated yet")

        data = crl_path.read_bytes()
        etag = hashlib.sha256(data).hexdigest()

        db.audit(session, actor=f"site:{site.radius_cn}", action="crl_pull", target=site.radius_cn, detail=f"etag={etag}")
        session.commit()

        if request.headers.get("if-none-match") == etag:
            return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

        return Response(content=data, media_type="application/x-pem-file", headers={"ETag": etag})

    @router.post("/server-cert/renew")
    def renew_server_cert(
        payload: dict,
        site: db.Site = Depends(deps.require_site),
    ):
        _enforce_rate_limit(site, "renew", RENEW_RATE_LIMIT)
        session = deps.get_db_session()

        csr_pem = payload.get("csr_pem")
        request_id = payload.get("request_id")
        if not csr_pem or not request_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "csr_pem and request_id are required")

        try:
            result = cert_service.issue_server_cert(
                session, deps.pki_path, deps.inter_cert, deps.inter_key,
                csr_pem=csr_pem.encode() if isinstance(csr_pem, str) else csr_pem,
                site_id=site.id,
                site_cn=site.radius_cn,
                request_id=request_id,
                days=deps.server_cert_days,
                issued_by=f"site:{site.radius_cn}",
            )
        except cert_service.CSRCNMismatchError:
            # No CSR/CN detail in the response body — a mismatch is exactly
            # the "one site tried to get another site's identity" case,
            # and the error shouldn't help an attacker calibrate a retry.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSR rejected")

        site.server_cert_id = result.certificate.id
        session.commit()

        cert_pem = (deps.pki_path / "issued" / f"{site.radius_cn}.{result.certificate.serial}.crt").read_bytes()
        ca_chain_path = deps.pki_path / "ca-chain.pem"
        ca_chain_pem = ca_chain_path.read_bytes() if ca_chain_path.exists() else b""

        return {
            "cert_pem": cert_pem.decode(),
            "ca_chain_pem": ca_chain_pem.decode(),
            "serial": result.certificate.serial,
            "not_after": result.certificate.expires_at.isoformat(),
        }

    return router
