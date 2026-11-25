"""Synthetic auth canary (handoff task O2): eapol_test subprocess wrapper
and DB wiring. Every subprocess call is mocked — this must never spawn a
real eapol_test process (same rule as the rest of this suite)."""

import datetime
import socket
import uuid
from unittest.mock import MagicMock

from app import canary, db


def _site(**overrides):
    defaults = dict(
        id=str(uuid.uuid4()), name="Boracay", radius_cn="radius-boracay.internal",
        auth_token_hash="x", crl_validity_days=30, checkin_interval_seconds=3600,
        is_active=True,
    )
    defaults.update(overrides)
    return db.Site(**defaults)


def _write_canary_files(pki_path, site):
    out_dir = canary.canary_dir(pki_path, site)
    out_dir.mkdir(parents=True)
    (out_dir / "client.key").write_bytes(b"fake key")
    (out_dir / "client.crt").write_bytes(b"fake cert")
    (pki_path / "ca-chain.pem").write_bytes(b"fake chain")


def test_run_probe_fails_when_cert_files_missing(tmp_path):
    site = _site()
    result = canary.run_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "missing required file" in result.detail


def test_run_probe_succeeds_on_eapol_test_success(tmp_path, monkeypatch):
    site = _site()
    _write_canary_files(tmp_path, site)

    monkeypatch.setattr(canary.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(
        canary.subprocess, "run",
        lambda cmd, **k: MagicMock(returncode=0, stdout="...\nSUCCESS\n", stderr=""),
    )

    result = canary.run_probe(site, tmp_path, secret="s3cret")
    assert result.ok is True


def test_run_probe_fails_on_eapol_test_failure(tmp_path, monkeypatch):
    site = _site()
    _write_canary_files(tmp_path, site)

    monkeypatch.setattr(canary.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(
        canary.subprocess, "run",
        lambda cmd, **k: MagicMock(returncode=1, stdout="FAILURE\n", stderr="TLS handshake failed"),
    )

    result = canary.run_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "TLS handshake failed" in result.detail


def test_run_probe_handles_missing_eapol_test_binary(tmp_path, monkeypatch):
    site = _site()
    _write_canary_files(tmp_path, site)

    def _raise(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(canary.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(canary.subprocess, "run", _raise)

    result = canary.run_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "not found" in result.detail


def test_run_probe_handles_timeout(tmp_path, monkeypatch):
    import subprocess as sp
    site = _site()
    _write_canary_files(tmp_path, site)

    def _raise(*a, **k):
        raise sp.TimeoutExpired(cmd="eapol_test", timeout=15)

    monkeypatch.setattr(canary.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(canary.subprocess, "run", _raise)

    result = canary.run_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "timed out" in result.detail


def test_run_probe_fails_when_hostname_does_not_resolve(tmp_path, monkeypatch):
    site = _site()
    _write_canary_files(tmp_path, site)

    def _raise(h):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(canary.socket, "gethostbyname", _raise)

    result = canary.run_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "could not resolve" in result.detail


def test_record_probe_result_updates_site_and_audits_on_failure(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    site = _site()
    session.add(site)
    session.commit()

    canary.record_probe_result(session, site, canary.CanaryResult(ok=False, detail="boom"))

    assert site.last_canary_ok is False
    assert site.last_canary_checked_at is not None
    audit_rows = session.query(db.AuditLog).filter_by(action="canary_probe_failed").all()
    assert len(audit_rows) == 1


def test_record_probe_result_no_audit_on_success(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    site = _site()
    session.add(site)
    session.commit()

    canary.record_probe_result(session, site, canary.CanaryResult(ok=True, detail="fine"))

    assert site.last_canary_ok is True
    assert session.query(db.AuditLog).filter_by(action="canary_probe_failed").count() == 0


def _write_revoked_canary_files(pki_path, site):
    out_dir = canary.revoked_canary_dir(pki_path, site)
    out_dir.mkdir(parents=True)
    (out_dir / "client.key").write_bytes(b"fake key")
    (out_dir / "client.crt").write_bytes(b"fake cert")
    (pki_path / "ca-chain.pem").write_bytes(b"fake chain")


def test_run_revoked_probe_ok_when_eapol_test_rejects(tmp_path, monkeypatch):
    site = _site()
    _write_revoked_canary_files(tmp_path, site)

    monkeypatch.setattr(canary.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(
        canary.subprocess, "run",
        lambda cmd, **k: MagicMock(returncode=1, stdout="FAILURE\n", stderr="certificate revoked"),
    )

    result = canary.run_revoked_probe(site, tmp_path, secret="s3cret")
    assert result.ok is True


def test_run_revoked_probe_alerts_when_eapol_test_succeeds(tmp_path, monkeypatch):
    # The failure mode P1's acceptance test caught: check_crl silently
    # stops enforcing, so the revoked cert authenticates successfully.
    site = _site()
    _write_revoked_canary_files(tmp_path, site)

    monkeypatch.setattr(canary.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(
        canary.subprocess, "run",
        lambda cmd, **k: MagicMock(returncode=0, stdout="...\nSUCCESS\n", stderr=""),
    )

    result = canary.run_revoked_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "not enforcing" in result.detail


def test_run_revoked_probe_fails_when_cert_files_missing(tmp_path):
    site = _site()
    result = canary.run_revoked_probe(site, tmp_path, secret="s3cret")
    assert result.ok is False
    assert "missing required file" in result.detail


def test_record_revoked_probe_result_updates_site_and_audits_on_failure(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    site = _site()
    session.add(site)
    session.commit()

    canary.record_revoked_probe_result(session, site, canary.CanaryResult(ok=False, detail="boom"))

    assert site.last_revoked_canary_ok is False
    assert site.last_revoked_canary_checked_at is not None
    audit_rows = session.query(db.AuditLog).filter_by(action="revoked_canary_probe_failed").all()
    assert len(audit_rows) == 1


def test_record_revoked_probe_result_no_audit_on_success(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    site = _site()
    session.add(site)
    session.commit()

    canary.record_revoked_probe_result(session, site, canary.CanaryResult(ok=True, detail="fine"))

    assert site.last_revoked_canary_ok is True
    assert session.query(db.AuditLog).filter_by(action="revoked_canary_probe_failed").count() == 0


def test_issue_revoked_canary_certificate_revokes_and_links_site(throwaway_pki):
    tmp_path = throwaway_pki["tmp_path"]
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    subsidiary = db.Subsidiary(id=str(uuid.uuid4()), code="ACME", display_name="Acme")
    role = db.NetworkRole(id=str(uuid.uuid4()), subsidiary_id=subsidiary.id, code="corp", display_name="Corp")
    site = _site()
    session.add_all([subsidiary, role, site])
    session.commit()

    cert = canary.issue_revoked_canary_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], site,
        subsidiary_id=subsidiary.id, network_role_id=role.id, issued_by="test",
    )

    assert site.revoked_canary_cert_id == cert.id
    assert cert.status == db.CertStatus.revoked
    assert cert.cn == canary.revoked_canary_cn(site)
    key_path = canary.revoked_canary_dir(tmp_path, site) / "client.key"
    assert key_path.is_file()
