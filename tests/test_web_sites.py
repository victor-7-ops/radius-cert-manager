"""Site management UI (HANDOFF-COMPLIANCE.md §4) — Super Admin only."""

from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki, site_service
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username, role):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username=username, password_hash=auth.hash_password("correcthorse123"), role=role)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def _client(app_settings, throwaway_pki, monkeypatch, role=db.AdminRole.super_admin, username="root-admin"):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, username, role)
    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)
    return client


def test_create_list_rotate_deactivate_reactivate(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)

    resp = client.post(
        "/sites",
        data={"name": "Boracay RADIUS", "radius_cn": "radius-boracay", "subsidiary": db.SUBSIDIARIES[0]},
    )
    assert resp.status_code == 200
    assert "shown once" in resp.text
    assert "Boracay RADIUS" in resp.text

    resp = client.get("/sites")
    assert resp.status_code == 200
    assert "Boracay RADIUS" in resp.text
    assert "radius-boracay" in resp.text

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    from sqlalchemy import select
    site = session.scalar(select(db.Site).where(db.Site.radius_cn == "radius-boracay"))
    assert site is not None
    old_hash = site.auth_token_hash

    resp = client.post(f"/sites/{site.id}/rotate-token")
    assert resp.status_code == 200
    assert "shown once" in resp.text
    session.refresh(site)
    assert site.auth_token_hash != old_hash

    resp = client.post(f"/sites/{site.id}/deactivate", follow_redirects=False)
    assert resp.status_code == 303
    session.refresh(site)
    assert site.is_active is False

    resp = client.get("/sites")
    assert "Inactive" in resp.text

    resp = client.post(f"/sites/{site.id}/reactivate", follow_redirects=False)
    assert resp.status_code == 303
    session.refresh(site)
    assert site.is_active is True


def test_invalid_radius_cn_rejected(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    resp = client.post("/sites", data={"name": "x", "radius_cn": "../../etc/passwd"})
    assert resp.status_code == 400
    assert "Invalid radius_cn" in resp.text


def test_invalid_subsidiary_rejected(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    resp = client.post("/sites", data={"name": "x", "radius_cn": "radius-x", "subsidiary": "Not A Real Company"})
    assert resp.status_code == 400
    assert "Invalid subsidiary" in resp.text


def test_regular_admin_cannot_access_sites_ui(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch, role=db.AdminRole.admin, username="regular-admin")
    assert client.get("/sites").status_code == 403
    assert client.post("/sites", data={"name": "x", "radius_cn": "radius-x"}).status_code == 403


def test_viewer_cannot_access_sites_ui(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch, role=db.AdminRole.viewer, username="viewer-1")
    assert client.get("/sites").status_code == 403
