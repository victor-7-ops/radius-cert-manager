"""Site agent install-safety logic (HANDOFF-FLEET.md §3.4/§4.4). Every
subprocess call (openssl, freeradius, systemctl) and every network call
is mocked — this test must never touch a real FreeRADIUS process or make
a real HTTP request (same rule as the rest of this suite, handoff §12)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "agent"))

import site_agent  # noqa: E402


def _ok(stdout="", stderr=""):
    return MagicMock(returncode=0, stdout=stdout, stderr=stderr)


def _fail(stdout="", stderr="boom"):
    return MagicMock(returncode=1, stdout=stdout, stderr=stderr)


def _make_cfg(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    cfg = site_agent.Config.__new__(site_agent.Config)
    cfg.hub_url = "https://hub.example"
    cfg.token = "tok"
    cfg.site_cn = "radius-x.internal"
    cfg.cert_dir = cert_dir
    cfg.state_dir = tmp_path / "state"
    cfg.crl_filename = "crl.pem"
    cfg.server_cert_filename = "server.pem"
    cfg.server_key_filename = "server.key"
    cfg.ca_chain_filename = "ca-chain.pem"
    cfg.freeradius_service = "freeradius"
    cfg.request_timeout = 5.0
    return cfg


def test_install_with_safety_succeeds_and_writes_new_content(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    monkeypatch.setattr(site_agent, "_run", lambda cmd, **k: _ok())
    monkeypatch.setattr(site_agent, "_freeradius_is_active", lambda service: True)
    monkeypatch.setattr(site_agent.time, "sleep", lambda s: None)

    target = cfg.cert_dir / "server.pem"
    ok = site_agent._install_with_safety(cfg, {target: b"NEW CERT"}, label="server-cert")

    assert ok is True
    assert target.read_bytes() == b"NEW CERT"


def test_install_with_safety_rolls_back_on_freeradius_check_failure(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    target = cfg.cert_dir / "server.pem"
    target.write_bytes(b"OLD CERT")

    def fake_run(cmd, **k):
        if cmd[:2] == ["freeradius", "-XC"]:
            return _fail()
        return _ok()

    monkeypatch.setattr(site_agent, "_run", fake_run)
    reload_calls = []
    monkeypatch.setattr(
        site_agent, "_freeradius_reload",
        lambda service: (reload_calls.append(service) or (True, "")),
    )

    ok = site_agent._install_with_safety(cfg, {target: b"BAD CERT"}, label="server-cert")

    assert ok is False
    assert target.read_bytes() == b"OLD CERT"  # rolled back
    assert reload_calls  # reload attempted after rollback, per §3.4


def test_install_with_safety_rolls_back_on_reload_failure(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    target = cfg.cert_dir / "crl.pem"
    target.write_bytes(b"OLD CRL")

    monkeypatch.setattr(site_agent, "_run", lambda cmd, **k: _ok())
    monkeypatch.setattr(site_agent, "_freeradius_reload", lambda service: (False, "reload failed"))

    ok = site_agent._install_with_safety(cfg, {target: b"NEW CRL"}, label="crl")

    assert ok is False
    assert target.read_bytes() == b"OLD CRL"


def test_install_with_safety_rolls_back_when_freeradius_not_active_after_reload(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    target = cfg.cert_dir / "crl.pem"
    target.write_bytes(b"OLD CRL")

    monkeypatch.setattr(site_agent, "_run", lambda cmd, **k: _ok())
    monkeypatch.setattr(site_agent, "_freeradius_reload", lambda service: (True, ""))
    monkeypatch.setattr(site_agent, "_freeradius_is_active", lambda service: False)
    monkeypatch.setattr(site_agent.time, "sleep", lambda s: None)

    ok = site_agent._install_with_safety(cfg, {target: b"NEW CRL"}, label="crl")

    assert ok is False
    assert target.read_bytes() == b"OLD CRL"


def test_install_with_safety_restores_absence_when_file_did_not_exist_before(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    target = cfg.cert_dir / "ca-chain.pem"
    assert not target.exists()

    monkeypatch.setattr(site_agent, "_run", lambda cmd, **k: _fail())

    ok = site_agent._install_with_safety(cfg, {target: b"NEW CHAIN"}, label="server-cert")

    assert ok is False
    assert not target.exists()


def test_fetch_and_install_crl_refuses_expired_next_update(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200, content=b"FAKE CRL BYTES")

    # openssl crl -noout -nextupdate parse succeeds, but date -d gives a
    # timestamp in the past.
    def fake_run(cmd, **k):
        if cmd[0] == "openssl":
            return _ok(stdout="nextUpdate=Jan  1 00:00:00 2000 GMT")
        if cmd[0] == "date":
            return _ok(stdout="1")  # epoch 1 — far in the past
        return _ok()

    monkeypatch.setattr(site_agent, "_run", fake_run)
    install_calls = []
    monkeypatch.setattr(
        site_agent, "_install_with_safety",
        lambda cfg, files, label: install_calls.append(1) or True,
    )

    result = site_agent.fetch_and_install_crl(cfg, session, reported_etag=None)

    assert result is None
    assert not install_calls  # must never reach the install step


def test_fetch_and_install_crl_returns_304_as_no_op(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=304)

    result = site_agent.fetch_and_install_crl(cfg, session, reported_etag="abc")

    assert result is None
    session.get.assert_called_once()


def test_fetch_and_install_crl_installs_when_next_update_is_future(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    session = MagicMock()
    session.get.return_value = MagicMock(status_code=200, content=b"FAKE CRL BYTES")

    def fake_run(cmd, **k):
        if cmd[0] == "openssl":
            return _ok(stdout="nextUpdate=Jan  1 00:00:00 2099 GMT")
        if cmd[0] == "date":
            return _ok(stdout="4102444800")  # far future epoch
        return _ok()

    monkeypatch.setattr(site_agent, "_run", fake_run)
    monkeypatch.setattr(site_agent, "_install_with_safety", lambda cfg, files, label: True)

    result = site_agent.fetch_and_install_crl(cfg, session, reported_etag=None)

    assert result == site_agent._sha256_bytes(b"FAKE CRL BYTES")


def test_renew_server_cert_rejects_when_hub_rejects_csr(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    session = MagicMock()
    session.post.return_value = MagicMock(status_code=403, text="CSR rejected")

    monkeypatch.setattr(site_agent, "_run", lambda cmd, **k: _ok())
    monkeypatch.setattr(
        site_agent, "_generate_key_and_csr",
        lambda cn, work_dir: _fake_keypair(work_dir),
    )

    ok = site_agent.renew_server_cert(cfg, session)

    assert ok is False


def test_renew_server_cert_installs_returned_cert_on_success(tmp_path, monkeypatch):
    cfg = _make_cfg(tmp_path)
    session = MagicMock()
    session.post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"cert_pem": "CERT", "ca_chain_pem": "CHAIN", "serial": "123"},
    )

    monkeypatch.setattr(
        site_agent, "_generate_key_and_csr",
        lambda cn, work_dir: _fake_keypair(work_dir),
    )
    install_calls = []
    monkeypatch.setattr(
        site_agent, "_install_with_safety",
        lambda cfg, files, label: install_calls.append(files) or True,
    )

    ok = site_agent.renew_server_cert(cfg, session)

    assert ok is True
    staged = install_calls[0]
    assert staged[cfg.cert_dir / cfg.server_cert_filename] == b"CERT"
    assert staged[cfg.cert_dir / cfg.server_key_filename] == b"FAKE KEY BYTES"


def _fake_keypair(work_dir: Path):
    work_dir.mkdir(parents=True, exist_ok=True)
    key_path = work_dir / "server_new.key"
    csr_path = work_dir / "server_new.csr"
    key_path.write_bytes(b"FAKE KEY BYTES")
    csr_path.write_text("FAKE CSR PEM")
    return key_path, csr_path
