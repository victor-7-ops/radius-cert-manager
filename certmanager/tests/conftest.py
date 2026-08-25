"""Throwaway test PKI, built fresh under tmp_path for every test.

Non-negotiable (handoff §12): tests never touch the live PKI or the live
CM4. If a test could conceivably write to PKI_PATH or SSH to RADIUS_HOST,
it is wrong.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import pki  # noqa: E402


@pytest.fixture
def throwaway_pki(tmp_path):
    root_cert, root_key = pki.build_self_signed_ca("Test Root CA", days=15 * 365)
    inter_cert, inter_key = pki.build_intermediate_ca(
        "Test Issuing CA", 5 * 365, root_cert, root_key
    )
    return {
        "root_cert": root_cert,
        "root_key": root_key,
        "inter_cert": inter_cert,
        "inter_key": inter_key,
        "tmp_path": tmp_path,
    }


@pytest.fixture(autouse=True)
def _no_live_env(monkeypatch):
    # Belt-and-suspenders: ensure nothing accidentally points at real paths/hosts.
    monkeypatch.delenv("PKI_PATH", raising=False)
    monkeypatch.delenv("RADIUS_HOST", raising=False)


@pytest.fixture
def app_settings(tmp_path, monkeypatch):
    pki_dir = tmp_path / "pki"
    (pki_dir / "private").mkdir(parents=True)
    (pki_dir / "issued").mkdir(parents=True)
    env = {
        "SECRET_KEY": "x" * 40,
        "PKI_PATH": str(pki_dir),
        "DB_PATH": str(tmp_path / "certmanager.db"),
        "BIND_HOST": "127.0.0.1",
        "BIND_PORT": "8443",
        "RADIUS_HOST": "127.0.0.1",
        "RADIUS_SSH_KEY": str(tmp_path / "ssh_key"),
        "RADIUS_SSH_USER": "crlpush",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    (tmp_path / "ssh_key").write_text("fake")
    from app.config import load_settings

    return load_settings()
