"""Site registry + check-in/pull API (HANDOFF-FLEET.md §4). Covers: site
creation and token auth, checkin, CRL pull with ETag/304, server-cert
renewal end to end, cross-site isolation, and that agent routes reject
the admin session cookie."""

import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app import auth, cert_service, db, pki, site_service
from app.main import create_app
from tests.conftest import login_as


def _csr_pem(cn: str) -> bytes:
    key = pki.generate_private_key()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _make_app(tmp_path, monkeypatch, throwaway_pki):
    pki_dir = tmp_path / "pki"
    (pki_dir / "private").mkdir(parents=True)
    (pki_dir / "issued").mkdir(parents=True)
    (pki_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (pki_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )
    env = {
        "SECRET_KEY": "x" * 40, "PKI_PATH": str(pki_dir), "DB_PATH": str(tmp_path / "cm.db"),
        "BIND_HOST": "127.0.0.1", "BIND_PORT": "8443", "RADIUS_HOST": "test-radius-host",
        "RADIUS_SSH_KEY": str(tmp_path / "ssh_key"), "RADIUS_SSH_USER": "crlpush",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    (tmp_path / "ssh_key").write_text("fake")
    from app.config import load_settings

    app_settings = load_settings()
    app = create_app(app_settings)
    client = TestClient(app, base_url="https://testserver")
    return app, client, app_settings


def _super_admin(app_settings):
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username="alice", password_hash=auth.hash_password("correcthorse123"),
        role=db.AdminRole.super_admin,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return session, admin


def _create_site_via_api(client, app_settings, name="Boracay", radius_cn="radius-boracay.internal"):
    session, admin = _super_admin(app_settings)
    login_as(client, app_settings, admin)
    resp = client.post("/api/admin/sites", json={"name": name, "radius_cn": radius_cn})
    assert resp.status_code == 200, resp.text
    return resp.json(), session


def test_startup_seeds_one_site_from_radius_host(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    sites = session.query(db.Site).all()
    assert len(sites) == 1
    assert sites[0].radius_cn == "test-radius-host"


def test_create_site_returns_token_once_and_stores_only_hash(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    assert "token" in body and len(body["token"]) > 20

    site = session.query(db.Site).filter_by(radius_cn="radius-boracay.internal").one()
    assert site.auth_token_hash != body["token"]
    assert body["token"] not in site.auth_token_hash


def test_checkin_rejects_missing_or_bad_token(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    resp = client.post("/api/site/checkin", json={})
    assert resp.status_code == 401

    resp = client.post("/api/site/checkin", json={}, headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


def test_checkin_rejects_admin_session_cookie(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    session, admin = _super_admin(app_settings)
    login_as(client, app_settings, admin)
    # Admin cookie is set, but no Authorization header — agent routes
    # must not accept the cookie as a substitute for a site token.
    resp = client.post("/api/site/checkin", json={})
    assert resp.status_code == 401


def test_checkin_succeeds_with_valid_token_and_updates_last_seen(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    token = body["token"]

    resp = client.post(
        "/api/site/checkin",
        json={"agent_version": "1.0.0", "freeradius_ok": True, "crl_sha256": None},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "next_checkin_interval_seconds" in data

    engine = db.make_engine(str(app_settings.db_path))
    verify_session = db.make_session_factory(engine)()
    site = verify_session.query(db.Site).filter_by(radius_cn="radius-boracay.internal").one()
    assert site.last_seen_at is not None
    assert site.agent_version == "1.0.0"
    assert site.last_reported_freeradius_ok is True


def test_crl_pull_returns_304_when_etag_matches(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    token = body["token"]

    cert_service.regenerate_crl(
        session, app_settings.pki_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        validity_days=7,
    )

    resp1 = client.get("/api/site/crl", headers={"Authorization": f"Bearer {token}"})
    assert resp1.status_code == 200
    etag = resp1.headers["etag"]

    resp2 = client.get(
        "/api/site/crl",
        headers={"Authorization": f"Bearer {token}", "If-None-Match": etag},
    )
    assert resp2.status_code == 304


def test_server_cert_renewal_end_to_end(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    token = body["token"]

    csr_pem = _csr_pem("radius-boracay.internal")
    resp = client.post(
        "/api/site/server-cert/renew",
        json={"csr_pem": csr_pem.decode(), "request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "BEGIN CERTIFICATE" in data["cert_pem"]
    assert data["serial"]

    engine = db.make_engine(str(app_settings.db_path))
    verify_session = db.make_session_factory(engine)()
    site = verify_session.query(db.Site).filter_by(radius_cn="radius-boracay.internal").one()
    assert site.server_cert_id is not None
    cert = verify_session.get(db.Certificate, site.server_cert_id)
    assert cert.cert_type == "server"


def test_server_cert_renewal_rejects_csr_for_another_sites_cn(tmp_path, monkeypatch, throwaway_pki):
    """A site's token authenticates it as itself; it must not be able to
    submit a CSR bearing a different site's CN and get it signed."""
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    token = body["token"]

    csr_pem = _csr_pem("radius-someone-elses-site.internal")
    resp = client.post(
        "/api/site/server-cert/renew",
        json={"csr_pem": csr_pem.decode(), "request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


def test_deactivated_site_token_no_longer_authenticates(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    token = body["token"]

    site = session.query(db.Site).filter_by(radius_cn="radius-boracay.internal").one()
    site_service.deactivate(session, site, actor="alice")

    resp = client.post("/api/site/checkin", json={}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_rotate_token_invalidates_old_token(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    body, session = _create_site_via_api(client, app_settings)
    old_token = body["token"]

    resp = client.post(f"/api/admin/sites/{body['id']}/rotate-token")
    assert resp.status_code == 200
    new_token = resp.json()["token"]
    assert new_token != old_token

    old_resp = client.post("/api/site/checkin", json={}, headers={"Authorization": f"Bearer {old_token}"})
    assert old_resp.status_code == 401

    new_resp = client.post("/api/site/checkin", json={}, headers={"Authorization": f"Bearer {new_token}"})
    assert new_resp.status_code == 200


def test_create_site_rejects_duplicate_radius_cn(tmp_path, monkeypatch, throwaway_pki):
    app, client, app_settings = _make_app(tmp_path, monkeypatch, throwaway_pki)
    _create_site_via_api(client, app_settings)
    resp = client.post(
        "/api/admin/sites", json={"name": "Boracay 2", "radius_cn": "radius-boracay.internal"}
    )
    assert resp.status_code == 409
