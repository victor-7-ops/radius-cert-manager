"""Push crl.pem to the RADIUS server and reload FreeRADIUS, then verify.

Handoff §8.3/§8.4/§8.5: never assume a push succeeded — read the CRL back
from the CM4 and compare its hash to the local file. Tests must mock the
SSH call; they must never actually connect (handoff §12).
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PushResult:
    ok: bool
    detail: str


def _local_hash(crl_path: Path) -> str:
    return hashlib.sha256(crl_path.read_bytes()).hexdigest()


def push_crl(
    crl_path: Path,
    radius_host: str,
    ssh_user: str,
    ssh_key: Path,
    run: callable = subprocess.run,
) -> PushResult:
    """scp the CRL, trigger the forced-command reload, then read it back
    and compare hashes. `run` is injectable so tests can mock the SSH
    calls without ever connecting (handoff §12)."""
    # The service's $HOME isn't writable (non-root container user owns
    # neither /app nor /root), so the default ~/.ssh/known_hosts can't be
    # created -- StrictHostKeyChecking=yes with nowhere to write the
    # pinned key just fails outright. Keep known_hosts next to the key
    # itself, on the same persisted volume.
    known_hosts = ssh_key.with_name("known_hosts")
    host_key_opts = ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}"]

    scp_cmd = [
        "scp",
        "-O",  # force legacy SCP protocol -- OpenSSH 9+ defaults to SFTP,
               # but the forced-command script on the other end speaks
               # scp's own wire protocol (`scp -t`), not SFTP.
        "-i",
        str(ssh_key),
        *host_key_opts,
        str(crl_path),
        f"{ssh_user}@{radius_host}:crl.pem",
    ]
    scp = run(scp_cmd, capture_output=True, timeout=30)
    if scp.returncode != 0:
        return PushResult(ok=False, detail=f"scp failed: {scp.stderr!r}")

    # The forced-command in authorized_keys installs crl.pem and reloads
    # FreeRADIUS; ssh here just triggers it (handoff §8.4).
    ssh_cmd = [
        "ssh",
        "-i",
        str(ssh_key),
        *host_key_opts,
        f"{ssh_user}@{radius_host}",
    ]
    reload = run(ssh_cmd, capture_output=True, timeout=30)
    if reload.returncode != 0:
        return PushResult(ok=False, detail=f"reload failed: {reload.stderr!r}")

    verify_cmd = [
        "ssh",
        "-i",
        str(ssh_key),
        *host_key_opts,
        f"{ssh_user}@{radius_host}",
        "sha256sum-crl",
    ]
    verify = run(verify_cmd, capture_output=True, timeout=30)
    if verify.returncode != 0:
        return PushResult(ok=False, detail=f"verify failed: {verify.stderr!r}")

    remote_hash = verify.stdout.decode().strip().split()[0]
    local_hash = _local_hash(crl_path)
    if remote_hash != local_hash:
        return PushResult(ok=False, detail="hash mismatch after push")

    return PushResult(ok=True, detail="pushed and verified")
