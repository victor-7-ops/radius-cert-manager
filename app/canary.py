"""Synthetic authentication canary (handoff task O2, 24 Nov 2026).

Six incidents (27 Oct x3, 29 Oct, 13 Nov, 19 Nov) each left every
monitored signal green -- fresh CRL, healthy service, OK site status --
while every real authentication failed. Nothing in this codebase before
this module ever actually attempted an EAP-TLS handshake; everything
monitored infrastructure around auth, never auth itself.

The canary cert's PRIVATE KEY is retained on the hub permanently, under
pki_path/canary/<site>/ -- a deliberate, narrowly-scoped exception to
this system's usual "keys are never retained server-side for client
certs" rule (see cert_service.issue_certificate, which only ever writes
the public cert to disk). A canary identity that the hub re-uses to
probe on a schedule has no other way to exist. Kept out of
cert_service.issue_certificate entirely -- that function is shared by
every real issuance path and is not the place to bolt on an exception
this narrow.
"""

from __future__ import annotations

import datetime
import logging
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app import ap_secrets, cert_service, db, pki

logger = logging.getLogger("certmanager.canary")

HUB_CANARY_AP_NAME = "hub-canary"
EAPOL_TEST_TIMEOUT_SECONDS = 15
CANARY_CERT_DAYS = 3650  # long-lived on purpose -- this is an operational
# test identity renewed by hand when it's actually close to expiry, not a
# real credential on the normal per-employee renewal cadence.


def canary_cn(site: db.Site) -> str:
    return f"canary-{site.radius_cn}"


def canary_dir(pki_path: Path, site: db.Site) -> Path:
    return pki_path / "canary" / site.radius_cn


def issue_canary_certificate(
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    site: db.Site,
    subsidiary_id: str,
    network_role_id: str,
    issued_by: str,
) -> db.Certificate:
    """Issues a real client cert through the same signing primitives as
    cert_service.issue_certificate (real OU=network_role_id, same CA),
    but retains the private key -- see module docstring. Marks the
    resulting Certificate.is_canary=True and links it from
    site.canary_cert_id, same FK pattern as site.server_cert_id."""
    cn = canary_cn(site)
    key = pki.generate_private_key()
    csr = pki.build_csr(key, cn)
    serial = cert_service._unique_serial(session)
    cert = pki.sign_client_cert(
        csr, inter_cert, inter_key, serial, CANARY_CERT_DAYS,
        subsidiary_id=subsidiary_id, network_role_id=network_role_id,
    )

    out_dir = canary_dir(pki_path, site)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "client.key"
    cert_path = out_dir / "client.crt"
    key_path.write_bytes(pki.private_key_to_pem(key))
    key_path.chmod(0o600)
    cert_path.write_bytes(pki.cert_to_pem(cert))

    row = db.Certificate(
        cn=cn,
        serial=str(serial),
        issued_at=cert.not_valid_before_utc,
        expires_at=cert.not_valid_after_utc,
        status=db.CertStatus.active,
        issued_by=issued_by,
        request_id=f"canary-{site.id}-{serial}",
        note=f"Synthetic auth canary for {site.name} ({site.radius_cn}) -- do not revoke during cleanup",
        employee_name="Synthetic Canary",
        cert_type="client",
        is_canary=True,
        subsidiary_id=subsidiary_id,
        network_role_id=network_role_id,
        identity_schema_version=2,
    )
    session.add(row)
    session.flush()
    site.canary_cert_id = row.id
    session.commit()
    return row


@dataclass
class CanaryResult:
    ok: bool
    detail: str


def run_probe(
    site: db.Site,
    pki_path: Path,
    secret: str,
    server_ip: str | None = None,
    timeout: int = EAPOL_TEST_TIMEOUT_SECONDS,
) -> CanaryResult:
    """Runs eapol_test against this site's FreeRADIUS, from the hub --
    deliberately from here, not from the box itself, since the whole
    point is to exercise the real network path an AP uses (the 13 Nov
    incident -- an AP missing from clients.conf, packets silently
    dropped -- is invisible to a probe run from the box's own loopback).
    The hub's own IP must be a registered client (AccessPoint row named
    "hub-canary", task M's clients.conf plumbing) on every probed site."""
    out_dir = canary_dir(pki_path, site)
    key_path = out_dir / "client.key"
    cert_path = out_dir / "client.crt"
    ca_chain_path = pki_path / "ca-chain.pem"

    for required in (key_path, cert_path, ca_chain_path):
        if not required.is_file():
            return CanaryResult(ok=False, detail=f"missing required file: {required}")

    hostname = server_ip or site.radius_cn
    try:
        # eapol_test's hostapd_parse_ip_addr() only accepts a numeric
        # address -- a hostname makes it hit an assert(0) and crash the
        # whole process (confirmed live 25 Nov 2026: topline-freeradius1
        # has no crl_push_host set, so it fell back to its hostname CN
        # and eapol_test aborted every run).
        host = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        return CanaryResult(ok=False, detail=f"could not resolve {hostname!r} to an IP: {exc}")
    config = (
        "network={{\n"
        '    ssid="radius-canary"\n'
        "    key_mgmt=WPA-EAP\n"
        "    eap=TLS\n"
        '    identity="{cn}"\n'
        '    ca_cert="{ca}"\n'
        '    client_cert="{cert}"\n'
        '    private_key="{key}"\n'
        "}}\n"
    ).format(cn=canary_cn(site), ca=ca_chain_path, cert=cert_path, key=key_path)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write(config)
        config_path = f.name

    try:
        result = subprocess.run(
            ["eapol_test", "-c", config_path, "-a", host, "-s", secret],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CanaryResult(ok=False, detail=f"eapol_test timed out after {timeout}s against {host}")
    except FileNotFoundError:
        return CanaryResult(ok=False, detail="eapol_test binary not found on this host")
    finally:
        Path(config_path).unlink(missing_ok=True)

    output = (result.stdout + result.stderr)[-2000:]
    ok = result.returncode == 0 and "SUCCESS" in result.stdout
    return CanaryResult(ok=ok, detail=output if not ok else "authenticated successfully")


def record_probe_result(session: Session, site: db.Site, result: CanaryResult) -> None:
    site.last_canary_ok = result.ok
    site.last_canary_checked_at = datetime.datetime.now(datetime.timezone.utc)
    if not result.ok:
        db.audit(
            session, actor="system", action="canary_probe_failed", target=site.radius_cn,
            detail=result.detail[:500], subsidiary=site.subsidiary, site_id=site.id,
        )
    session.commit()
