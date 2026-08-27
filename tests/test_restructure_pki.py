"""scripts/restructure_pki.py runs against a throwaway output tree only —
never against the live PKI (handoff §12)."""

import importlib.util
import sys
from pathlib import Path

from cryptography import x509

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "restructure_pki.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("restructure_pki", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_refuses_out_root_inside_repo(monkeypatch, capsys):
    module = _load_module()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "restructure_pki.py",
            "--out-root",
            str(SCRIPT_PATH.parent),  # inside the repo — must be refused
            "--out-service",
            str(SCRIPT_PATH.parent),
        ],
    )
    rc = module.main()
    assert rc == 1
    assert "removable media" in capsys.readouterr().err


def test_builds_full_chain_and_reissues_server_cert(tmp_path, monkeypatch):
    module = _load_module()
    out_root = tmp_path / "removable"
    out_service = tmp_path / "service_pki"

    monkeypatch.setattr("getpass.getpass", lambda prompt="": "a-sufficiently-long-passphrase-1")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "restructure_pki.py",
            "--out-root",
            str(out_root),
            "--out-service",
            str(out_service),
            "--root-days",
            "100",
            "--intermediate-days",
            "50",
            "--client-days",
            "10",
        ],
    )
    rc = module.main()
    assert rc == 0

    root_key_pem = (out_root / "root.key.pem").read_bytes()
    assert b"ENCRYPTED" in root_key_pem

    inter_cert = x509.load_pem_x509_certificate((out_service / "intermediate.crt").read_bytes())
    root_cert = x509.load_pem_x509_certificate((out_root / "root.crt.pem").read_bytes())
    assert inter_cert.issuer == root_cert.subject

    chain = (out_service / "ca-chain.pem").read_bytes()
    assert chain.count(b"BEGIN CERTIFICATE") == 2

    server_cert = x509.load_pem_x509_certificate(
        (out_service / "issued" / "radius-server.crt").read_bytes()
    )
    assert server_cert.issuer == inter_cert.subject
    assert (out_service / "radius-server.key.pem").exists()

    intermediate_key_pem = (out_service / "private" / "intermediate.key").read_bytes()
    assert b"ENCRYPTED" not in intermediate_key_pem  # §5.1 trap — must stay unencrypted
