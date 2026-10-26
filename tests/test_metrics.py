import datetime
import uuid

import pytest
from fastapi.testclient import TestClient

from app import auth, crl_push, db, metrics, pki
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username="metrics-admin", password_hash=auth.hash_password("correcthorse123"), role=db.AdminRole.super_admin)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_collect_metrics_format(app_settings, throwaway_pki):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    now = datetime.datetime.now(datetime.timezone.utc)
    # Add sample certificates
    c1 = db.Certificate(
        cn="alice",
        serial="1001",
        issued_at=now - datetime.timedelta(days=10),
        expires_at=now + datetime.timedelta(days=5),  # within 7d
        status=db.CertStatus.active,
        cert_type="client",
        subsidiary="Solaris",
        request_id=str(uuid.uuid4()),
        issued_by="admin",
    )
    c2 = db.Certificate(
        cn="bob",
        serial="1002",
        issued_at=now - datetime.timedelta(days=10),
        expires_at=now + datetime.timedelta(days=20),  # within 30d
        status=db.CertStatus.active,
        cert_type="client",
        subsidiary="Astra",
        request_id=str(uuid.uuid4()),
        issued_by="admin",
    )
    c3 = db.Certificate(
        cn="revoked-dev",
        serial="1003",
        issued_at=now - datetime.timedelta(days=10),
        expires_at=now + datetime.timedelta(days=100),
        status=db.CertStatus.revoked,
        cert_type="client",
        request_id=str(uuid.uuid4()),
        issued_by="admin",
    )
    session.add_all([c1, c2, c3])
    session.commit()

    output = metrics.collect_metrics(session, now=now)

    assert "radius_up 1" in output
    assert '# TYPE radius_certificates_count gauge' in output
    assert 'radius_certificates_count{status="active",type="client"} 2' in output
    assert 'radius_certificates_count{status="revoked",type="client"} 1' in output
    assert 'radius_certificates_subsidiary_count{subsidiary="Solaris"} 1' in output
    assert 'radius_certificates_subsidiary_count{subsidiary="Astra"} 1' in output
    assert 'radius_certificates_expiring_soon{window="7d"} 1' in output
    assert 'radius_certificates_expiring_soon{window="14d"} 1' in output
    assert 'radius_certificates_expiring_soon{window="30d"} 2' in output
    assert 'radius_crl_revoked_entries_count 1' in output
    assert 'radius_crl_is_critical' in output


def test_metrics_endpoint_response(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    _seed_admin(app_settings)

    app = create_app(app_settings)
    client = TestClient(app)

    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "version=0.0.4" in resp.headers["content-type"]
    assert "radius_up 1" in resp.text
    assert "radius_certificates_count" in resp.text
    assert "radius_crl_revoked_entries_count" in resp.text
