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

import datetime
import hashlib
import json
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
        self.hub_url_secondary = os.environ.get("HUB_URL_SECONDARY", "").rstrip("/")
        self.token = _require_env("SITE_TOKEN")
        self.site_cn = _require_env("SITE_CN")
        self.site_id = os.environ.get("SITE_ID", self.site_cn)
        self.cert_dir = Path(os.environ.get("CERT_DIR", "/etc/freeradius/3.0/certs"))
        self.state_dir = Path(os.environ.get("STATE_DIR", "/var/lib/certmanager-agent"))
        self.policy_dir = Path(os.environ.get("POLICY_DIR", "/etc/freeradius/3.0"))
        self.policy_filename = os.environ.get("POLICY_FILENAME", "policy.json")
        self.policy_public_key_file = os.environ.get("POLICY_PUBLIC_KEY_FILE", "")
        self.crl_filename = os.environ.get("CRL_FILENAME", "crl.pem")
        self.server_cert_filename = os.environ.get("SERVER_CERT_FILENAME", "server.pem")
        self.server_key_filename = os.environ.get("SERVER_KEY_FILENAME", "server.key")
        self.ca_chain_filename = os.environ.get("CA_CHAIN_FILENAME", "ca-chain.pem")
        self.freeradius_service = os.environ.get("FREERADIUS_SERVICE", "freeradius")
        self.radius_adapter_path = Path(
            os.environ.get("RADIUS_ADAPTER_PATH", "/opt/certmanager/deploy/radius/authorize_policy.py")
        )
        self.request_timeout = float(os.environ.get("REQUEST_TIMEOUT_SECONDS", "30"))
        self.hub_ca_bundle = _require_ca_bundle()
        self.policy_public_key_file = _require_file_env("POLICY_PUBLIC_KEY_FILE")


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def _require_file_env(name: str) -> str:
    value = _require_env(name)
    path = Path(value)
    if not path.is_file():
        raise SystemExit(f"{name} does not exist: {value}")
    try:
        if not path.read_bytes():
            raise OSError("file is empty")
    except OSError as exc:
        raise SystemExit(f"{name} is not readable: {value}: {exc}") from exc
    return value


def _require_ca_bundle() -> str:
    """HANDOFF-COMPLIANCE.md §5 (security defect): the hub's TLS cert is
    issued by the Arekushi intermediate, which isn't in the system trust
    store, so a bare requests.Session() fails verification against a real
    hub — and the obvious workaround under time pressure is verify=False,
    which exposes the CRL feed and CSR exchange to anyone on the network
    path. Fail closed: no bundle, no fallback to system trust, no
    fallback to no verification — just refuse to start."""
    value = os.environ.get("HUB_CA_BUNDLE")
    if not value:
        raise SystemExit("missing required environment variable: HUB_CA_BUNDLE")
    if not Path(value).is_file():
        raise SystemExit(f"HUB_CA_BUNDLE does not exist: {value}")
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


def _freeradius_restart(service: str) -> tuple[bool, str]:
    """A reload (SIGHUP) doesn't reimport Python modules inside rlm_python3,
    so an adapter code change needs a real restart to take effect."""
    result = _run(["systemctl", "restart", service])
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


def _install_with_safety(cfg: Config, staged_files: dict[Path, bytes], label: str, restart: bool = False) -> bool:
    """Stage -> validate -> install -> reload/restart -> verify -> rollback
    on any failure. staged_files maps final path -> new content. Pass
    restart=True for changes a SIGHUP reload won't pick up (e.g. Python
    module source, per _freeradius_restart). Returns True on a verified
    successful install."""
    apply = _freeradius_restart if restart else _freeradius_reload

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
            apply(cfg.freeradius_service)
            return False

        apply_ok, apply_detail = apply(cfg.freeradius_service)
        if not apply_ok:
            logger.error("%s: %s failed, rolling back: %s", label, "restart" if restart else "reload", apply_detail)
            state.restore()
            apply(cfg.freeradius_service)
            return False

        # Give the reload/restart a moment to take effect before checking.
        time.sleep(2)
        if not _freeradius_is_active(cfg.freeradius_service):
            logger.error("%s: freeradius not active after %s, rolling back", label, "restart" if restart else "reload")
            state.restore()
            apply(cfg.freeradius_service)
            return False

        logger.info("%s: installed and verified", label)
        return True
    except Exception:
        logger.exception("%s: unexpected error during install, rolling back", label)
        state.restore()
        apply(cfg.freeradius_service)
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


def _hub_request(
    cfg: Config, session: requests.Session, method: str, path: str, **kwargs
) -> requests.Response:
    secondary = getattr(cfg, "hub_url_secondary", "")
    urls = [cfg.hub_url]
    if secondary and secondary != cfg.hub_url:
        urls.append(secondary)

    timeout = kwargs.pop("timeout", cfg.request_timeout)
    last_exc = None
    resp = None
    for i, url in enumerate(urls):
        full_url = f"{url}{path}"
        try:
            if method.upper() == "GET":
                get_fn = getattr(session, "get", None)
                if get_fn is None:
                    return None
                resp = get_fn(full_url, timeout=timeout, **kwargs)
            elif method.upper() == "POST":
                post_fn = getattr(session, "post", None)
                if post_fn is None:
                    return None
                resp = post_fn(full_url, timeout=timeout, **kwargs)
            else:
                req_fn = getattr(session, "request", None)
                if req_fn is None:
                    return None
                resp = req_fn(method, full_url, timeout=timeout, **kwargs)

            status_code = getattr(resp, "status_code", None)
            if isinstance(status_code, int) and status_code >= 500 and i < len(urls) - 1:
                logger.warning(
                    "hub %s returned %s, failing over to secondary hub", url, status_code
                )
                continue
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if i < len(urls) - 1:
                logger.warning(
                    "hub %s unreachable (%s), failing over to secondary hub", url, exc
                )
                continue
    if last_exc:
        raise last_exc
    return resp


def fetch_and_install_crl(cfg: Config, session: requests.Session, reported_etag: str | None) -> str | None:
    """Returns the new sha256 hex if a newer CRL was pulled and installed,
    None if unchanged or the pull/install failed (logged, not raised —
    a CRL pull failure isn't fatal to the rest of this run)."""
    headers = {"Authorization": f"Bearer {cfg.token}"}
    if reported_etag:
        headers["If-None-Match"] = reported_etag
    try:
        resp = _hub_request(cfg, session, "GET", "/api/site/crl", headers=headers, timeout=cfg.request_timeout)
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

    def _is_ip(val: str) -> bool:
        import ipaddress
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    san_val = f"IP:{cn}" if _is_ip(cn) else f"DNS:{cn}"
    csr = _run([
        "openssl", "req", "-new", "-key", str(key_path), "-out", str(csr_path),
        "-subj", f"/CN={cn}",
        "-addext", f"subjectAltName = {san_val}",
    ])
    if csr.returncode != 0:
        # Fallback for OpenSSL versions that do not support -addext
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
        resp = _hub_request(
            cfg, session, "POST", "/api/site/server-cert/renew", json=payload, headers=headers,
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
    session.verify = cfg.hub_ca_bundle
    headers = {"Authorization": f"Bearer {cfg.token}"}

    reported_crl_sha256 = _sha256_file(cfg.cert_dir / cfg.crl_filename)
    server_cert_path = cfg.cert_dir / cfg.server_cert_filename
    server_cert_serial = _server_cert_serial(server_cert_path) if server_cert_path.exists() else None
    freeradius_ok = _freeradius_is_active(cfg.freeradius_service)

    try:
        resp = _hub_request(
            cfg,
            session,
            "POST",
            "/api/site/checkin",
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

    # Synchronize signed network policy (B05)
    policy_ok = fetch_and_install_policy(cfg, session)

    # Synchronize the signed FreeRADIUS adapter source itself -- a code
    # change ships by redeploying the hub, every site then picks it up
    # here on its next poll, same pull-only trust model as the policy above.
    adapter_ok = fetch_and_install_radius_adapter(cfg, session)

    return 0 if (policy_ok and adapter_ok) else 1


def _validate_cached_policy(cfg: Config, rev_file: Path) -> bool:
    """Validate the installed decoded policy before accepting an HTTP 304."""
    live_path = cfg.policy_dir / cfg.policy_filename
    try:
        payload = json.loads(live_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 2 or payload.get("site_id") != cfg.site_id:
            raise ValueError("cached policy schema/site does not match local configuration")
        revision = payload.get("revision")
        recorded_revision = int(rev_file.read_text().strip())
        if not isinstance(revision, int) or revision != recorded_revision:
            raise ValueError("cached policy revision does not match recorded revision")
        expires_at = datetime.datetime.fromisoformat(payload["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if expires_at <= datetime.datetime.now(datetime.timezone.utc):
            raise ValueError("cached policy lease has expired")
    except Exception as exc:
        logger.error("cached network policy is not usable: %s", exc)
        return False
    return True


def fetch_and_install_policy(cfg: Config, session: requests.Session) -> bool:
    headers = {"Authorization": f"Bearer {cfg.token}"}
    hash_file = cfg.state_dir / "policy_hash.txt"
    rev_file = cfg.state_dir / "policy_revision.txt"

    etag = hash_file.read_text().strip() if hash_file.exists() else None
    if etag:
        headers["If-None-Match"] = etag

    try:
        resp = _hub_request(
            cfg, session, "GET", "/api/site/network-policy", headers=headers, timeout=cfg.request_timeout
        )
    except requests.RequestException:
        logger.exception("network policy pull request failed")
        return False

    if resp is None:
        return True

    if resp.status_code == 304:
        if not _validate_cached_policy(cfg, rev_file):
            return False
        logger.info("network policy unchanged (304); cached lease remains valid")
        return True

    if resp.status_code != 200:
        logger.error("network policy pull failed: %s %s", resp.status_code, resp.text[:500])
        return False

    try:
        envelope = resp.json()
    except Exception:
        logger.exception("network policy payload was not valid JSON")
        return False

    try:
        from app import site_policy
        pub_key = site_policy.load_public_key_pem(Path(cfg.policy_public_key_file).read_bytes())
        current_rev = int(rev_file.read_text().strip()) if rev_file.exists() else None
        min_rev = current_rev if current_rev is not None else 1
        payload = site_policy.verify_policy_envelope(
            envelope,
            pub_key,
            expected_site_id=cfg.site_id,
            min_revision=min_rev,
        )
    except Exception as e:
        logger.error("network policy signature verification failed: %s", e)
        _send_policy_ack(cfg, session, revision=0, payload_hash=None, success=False, detail=str(e))
        return False

    new_hash = resp.headers.get("ETag") or hashlib.sha256(resp.content).hexdigest()
    old_hash = hash_file.read_text().strip() if hash_file.exists() else None
    if current_rev is not None and payload.get("revision") == current_rev and old_hash and new_hash != old_hash:
        detail = "same policy revision arrived with a different payload hash"
        logger.error(detail)
        _send_policy_ack(cfg, session, revision=current_rev, payload_hash=new_hash, success=False, detail=detail)
        return False

    policy_bytes = json.dumps(payload, indent=2).encode("utf-8")
    cfg.policy_dir.mkdir(parents=True, exist_ok=True)
    live_path = cfg.policy_dir / cfg.policy_filename
    installed = _install_with_safety(cfg, {live_path: policy_bytes}, label="network-policy")

    rev = payload.get("revision", 0)
    if installed:
        rev_file.write_text(str(rev))
        hash_file.write_text(new_hash)
        _send_policy_ack(cfg, session, revision=rev, payload_hash=new_hash, success=True, detail="Installed cleanly")
        return True
    else:
        _send_policy_ack(cfg, session, revision=rev, payload_hash=new_hash, success=False, detail="Installation safety check failed")
        return False


def _send_policy_ack(cfg: Config, session: requests.Session, revision: int, payload_hash: str | None, success: bool, detail: str) -> None:
    headers = {"Authorization": f"Bearer {cfg.token}"}
    try:
        _hub_request(
            cfg, session, "POST", "/api/site/network-policy/ack",
            json={
                "revision": revision,
                "payload_hash": payload_hash,
                "success": success,
                "detail": detail,
                "agent_version": AGENT_VERSION,
            },
            headers=headers,
            timeout=cfg.request_timeout,
        )
    except Exception:
        logger.warning("failed to send policy ack to hub")


def fetch_and_install_radius_adapter(cfg: Config, session: requests.Session) -> bool:
    """Pulls the hub's signed FreeRADIUS adapter source and installs it if
    changed. Verified the same way as the network policy -- Ed25519
    signature against the locally pinned POLICY_PUBLIC_KEY_FILE -- then
    staged through _install_with_safety(restart=True), so a bad bundle
    (fails freeradius -XC, or the service won't come back up) rolls back
    automatically and never leaves the adapter module in a broken state."""
    headers = {"Authorization": f"Bearer {cfg.token}"}
    hash_file = cfg.state_dir / "radius_adapter_hash.txt"

    etag = hash_file.read_text().strip() if hash_file.exists() else None
    if etag:
        headers["If-None-Match"] = etag

    try:
        resp = _hub_request(
            cfg, session, "GET", "/api/site/radius-adapter", headers=headers, timeout=cfg.request_timeout
        )
    except requests.RequestException:
        logger.exception("radius adapter pull request failed")
        return False

    if resp is None:
        return True

    if resp.status_code == 304:
        logger.info("radius adapter unchanged (304)")
        return True

    if resp.status_code == 404:
        logger.info("no radius adapter bundle published by hub")
        return True

    if resp.status_code != 200:
        logger.error("radius adapter pull failed: %s %s", resp.status_code, resp.text[:500])
        return False

    try:
        envelope = resp.json()
    except Exception:
        logger.exception("radius adapter payload was not valid JSON")
        return False

    try:
        from app import site_policy
        pub_key = site_policy.load_public_key_pem(Path(cfg.policy_public_key_file).read_bytes())
        payload = site_policy.verify_code_bundle_envelope(envelope, pub_key)
    except Exception as e:
        logger.error("radius adapter signature verification failed: %s", e)
        return False

    content = payload["content_bytes"]
    new_hash = payload["sha256"]

    if new_hash == etag:
        # Signed bundle matches what's already installed (e.g. after a
        # 200 without a matching If-None-Match comparison upstream).
        hash_file.write_text(new_hash)
        return True

    cfg.radius_adapter_path.parent.mkdir(parents=True, exist_ok=True)
    installed = _install_with_safety(
        cfg, {cfg.radius_adapter_path: content}, label="radius-adapter", restart=True
    )

    if installed:
        hash_file.write_text(new_hash)
        logger.info("radius adapter installed: sha256=%s version=%s", new_hash[:16], payload.get("version"))
        return True
    return False


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
