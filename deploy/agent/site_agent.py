#!/usr/bin/env python3
"""Site-side agent for a FreeRADIUS box (HANDOFF-FLEET.md §4.4).

Runs from a systemd timer, not as a daemon — every invocation is a single
idempotent pass: check in, pull a newer CRL if one exists, renew the
server cert if the hub says it's due. Standard library + `requests` only,
so it runs on a CM4 with no build chain; key/CSR generation shells out to
`openssl`, which is already present on any box running FreeRADIUS.

Install safety (§3.4) is non-negotiable and applies to both the CRL and
the server cert: stage -> `freeradius -XC` -> only on success install and
reload -> verify FreeRADIUS came back -> on ANY failure, restore what was
there before, reload again, and let the next check-in report it (via
freeradius_ok=False, which the fleet view already treats as CRITICAL).
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import requests

logger = logging.getLogger("site_agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

AGENT_VERSION = "1.0.0"


class Config:
    def __init__(self):
        self.hub_url = _require_env("HUB_URL").rstrip("/")
        self.token = _require_env("SITE_TOKEN")
        self.site_cn = _require_env("SITE_CN")
        self.cert_dir = Path(os.environ.get("CERT_DIR", "/etc/freeradius/3.0/certs"))
        self.state_dir = Path(os.environ.get("STATE_DIR", "/var/lib/certmanager-agent"))
        self.crl_filename = os.environ.get("CRL_FILENAME", "crl.pem")
        self.server_cert_filename = os.environ.get("SERVER_CERT_FILENAME", "server.pem")
        self.server_key_filename = os.environ.get("SERVER_KEY_FILENAME", "server.key")
        self.ca_chain_filename = os.environ.get("CA_CHAIN_FILENAME", "ca-chain.pem")
        self.freeradius_service = os.environ.get("FREERADIUS_SERVICE", "freeradius")
        self.request_timeout = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return _sha256_bytes(path.read_bytes())


def _freeradius_check() -> tuple[bool, str]:
    result = _run(["freeradius", "-XC"])
    ok = result.returncode == 0
    return ok, (result.stdout + result.stderr)[-2000:]


def _freeradius_reload(service: str) -> tuple[bool, str]:
    result = _run(["systemctl", "reload", service])
    return result.returncode == 0, (result.stdout + result.stderr)[-2000:]


def _freeradius_is_active(service: str) -> bool:
    result = _run(["systemctl", "is-active", "--quiet", service])
    return result.returncode == 0


class InstallState:
    """Tracks what's currently at CERT_DIR so a failed install can be
    rolled back byte-for-byte rather than just "reverted to nothing"."""

    def __init__(self, paths: list[Path]):
        self.paths = paths
        self._backup: dict[Path, bytes | None] = {}

    def snapshot(self) -> None:
        self._backup = {p: (p.read_bytes() if p.exists() else None) for p in self.paths}

    def restore(self) -> None:
        for path, content in self._backup.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(content)


def _install_with_safety(cfg: Config, staged_files: dict[Path, bytes], label: str) -> bool:
    """Stage -> validate -> install -> reload -> verify -> rollback on any
    failure. staged_files maps final path -> new content. Returns True on
    a verified successful install."""
    live_paths = list(staged_files.keys())
    state = InstallState(live_paths)
    state.snapshot()

    staging_dir = cfg.state_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    for path, content in staged_files.items():
        (staging_dir / path.name).write_bytes(content)

    try:
        for path, content in staged_files.items():
            path.write_bytes(content)
            path.chmod(0o640 if "key" in path.name else 0o644)

        ok, detail = _freeradius_check()
        if not ok:
            logger.error("%s: freeradius -XC failed after staging, rolling back: %s", label, detail)
            state.restore()
            _freeradius_reload(cfg.freeradius_service)
            return False

        reload_ok, reload_detail = _freeradius_reload(cfg.freeradius_service)
        if not reload_ok:
            logger.error("%s: reload failed, rolling back: %s", label, reload_detail)
            state.restore()
            _freeradius_reload(cfg.freeradius_service)
            return False

        # Give the reload a moment to take effect before checking.
        time.sleep(2)
        if not _freeradius_is_active(cfg.freeradius_service):
            logger.error("%s: freeradius not active after reload, rolling back", label)
            state.restore()
            _freeradius_reload(cfg.freeradius_service)
            return False

        logger.info("%s: installed and verified", label)
        return True
    except Exception:
        logger.exception("%s: unexpected error during install, rolling back", label)
        state.restore()
        _freeradius_reload(cfg.freeradius_service)
        return False


def _crl_next_update_epoch(crl_bytes: Path) -> int:
    result = _run(["openssl", "crl", "-in", str(crl_bytes), "-noout", "-nextupdate"])
    if result.returncode != 0:
        return 0
    # Output like "nextUpdate=Jan  1 00:00:00 2030 GMT"
    value = result.stdout.strip().split("=", 1)[-1]
    date_result = _run(["date", "-d", value, "+%s"])
    if date_result.returncode != 0:
        return 0
    try:
        return int(date_result.stdout.strip())
    except ValueError:
        return 0


def fetch_and_install_crl(cfg: Config, session: requests.Session, reported_etag: str | None) -> str | None:
    """Returns the new sha256 hex if a newer CRL was pulled and installed,
    None if unchanged or the pull/install failed (logged, not raised —
    a CRL pull failure isn't fatal to the rest of this run)."""
    headers = {"Authorization": f"Bearer {cfg.token}"}
    if reported_etag:
        headers["If-None-Match"] = reported_etag
    try:
        resp = session.get(f"{cfg.hub_url}/api/site/crl", headers=headers, timeout=cfg.request_timeout)
    except requests.RequestException:
        logger.exception("CRL fetch failed")
        return None

    if resp.status_code == 304:
        logger.info("CRL unchanged")
        return None
    if resp.status_code != 200:
        logger.error("CRL fetch returned %s", resp.status_code)
        return None

    crl_bytes = resp.content
    staging_path = cfg.state_dir / "staging" / "crl_candidate.pem"
    staging_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path.write_bytes(crl_bytes)

    # TRAP (§4.4): refuse to install a CRL whose nextUpdate is already in
    # the past — ported from deploy/crlpush_forced_command.sh's push-side
    # check, same logic, agent-side.
    next_update_epoch = _crl_next_update_epoch(staging_path)
    if next_update_epoch <= int(time.time()):
        logger.error("fetched CRL's nextUpdate is in the past (or unparseable) — refusing to install")
        return None

    live_path = cfg.cert_dir / cfg.crl_filename
    installed = _install_with_safety(cfg, {live_path: crl_bytes}, label="crl")
    if not installed:
        return None
    return _sha256_bytes(crl_bytes)


def _generate_key_and_csr(cn: str, work_dir: Path) -> tuple[Path, Path]:
    """Generates an EC P-256 key and CSR via openssl — never via a
    serialization path that could re-encrypt the key (§3.4 trap: the
    private key must never leave this box and must never end up
    password-protected, or FreeRADIUS's TLS stack rejects it)."""
    work_dir.mkdir(parents=True, exist_ok=True)
    key_path = work_dir / "server_new.key"
    csr_path = work_dir / "server_new.csr"

    keygen = _run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_path)])
    if keygen.returncode != 0:
        raise RuntimeError(f"key generation failed: {keygen.stderr}")
    key_path.chmod(0o600)

    csr = _run([
        "openssl", "req", "-new", "-key", str(key_path), "-out", str(csr_path),
        "-subj", f"/CN={cn}",
    ])
    if csr.returncode != 0:
        raise RuntimeError(f"CSR generation failed: {csr.stderr}")

    return key_path, csr_path


def renew_server_cert(cfg: Config, session: requests.Session) -> bool:
    work_dir = cfg.state_dir / "staging"
    try:
        key_path, csr_path = _generate_key_and_csr(cfg.site_cn, work_dir)
    except RuntimeError:
        logger.exception("could not generate key/CSR for server cert renewal")
        return False

    headers = {"Authorization": f"Bearer {cfg.token}"}
    payload = {"csr_pem": csr_path.read_text(), "request_id": str(uuid.uuid4())}
    try:
        resp = session.post(
            f"{cfg.hub_url}/api/site/server-cert/renew", json=payload, headers=headers,
            timeout=cfg.request_timeout,
        )
    except requests.RequestException:
        logger.exception("server cert renewal request failed")
        return False

    if resp.status_code != 200:
        logger.error("server cert renewal rejected: %s %s", resp.status_code, resp.text[:500])
        return False

    data = resp.json()
    new_key = key_path.read_bytes()
    new_cert = data["cert_pem"].encode()
    new_chain = data.get("ca_chain_pem", "").encode()

    staged = {
        cfg.cert_dir / cfg.server_key_filename: new_key,
        cfg.cert_dir / cfg.server_cert_filename: new_cert,
    }
    if new_chain:
        staged[cfg.cert_dir / cfg.ca_chain_filename] = new_chain

    return _install_with_safety(cfg, staged, label="server-cert")


def run_once(cfg: Config) -> int:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    headers = {"Authorization": f"Bearer {cfg.token}"}

    reported_crl_sha256 = _sha256_file(cfg.cert_dir / cfg.crl_filename)
    server_cert_path = cfg.cert_dir / cfg.server_cert_filename
    server_cert_serial = _server_cert_serial(server_cert_path) if server_cert_path.exists() else None
    freeradius_ok = _freeradius_is_active(cfg.freeradius_service)

    try:
        resp = session.post(
            f"{cfg.hub_url}/api/site/checkin",
            json={
                "agent_version": AGENT_VERSION,
                "freeradius_ok": freeradius_ok,
                "crl_sha256": reported_crl_sha256,
                "server_cert_serial": server_cert_serial,
            },
            headers=headers,
            timeout=cfg.request_timeout,
        )
        resp.raise_for_status()
        checkin_data = resp.json()
    except requests.RequestException:
        logger.exception("checkin failed — will still try a CRL pull, since pull recovers on its own")
        checkin_data = {"newer_crl_available": True, "renewal_due": False}

    if checkin_data.get("newer_crl_available"):
        fetch_and_install_crl(cfg, session, reported_etag=None)

    if checkin_data.get("renewal_due"):
        renew_server_cert(cfg, session)

    return 0


def _server_cert_serial(cert_path: Path) -> str | None:
    result = _run(["openssl", "x509", "-in", str(cert_path), "-noout", "-serial"])
    if result.returncode != 0:
        return None
    # Output like "serial=1A2B3C" — hub stores decimal serials, so convert.
    hex_serial = result.stdout.strip().split("=", 1)[-1]
    try:
        return str(int(hex_serial, 16))
    except ValueError:
        return None


def main() -> int:
    cfg = Config()
    return run_once(cfg)


if __name__ == "__main__":
    sys.exit(main())
