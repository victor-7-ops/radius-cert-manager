"""Super Admin UI for subsidiaries/departments/roles/site authorization
and VLAN bindings (app/routes/web_subsidiaries.py)."""

from sqlalchemy import select

from app import auth, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as
from fastapi.testclient import TestClient


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


def test_create_subsidiary_and_list(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)

    resp = client.post("/subsidiaries", data={"code": "acme", "display_name": "Acme Corp"}, follow_redirects=False)
    assert resp.status_code == 303

    resp = client.get("/subsidiaries")
    assert resp.status_code == 200
    assert "Acme Corp" in resp.text


def test_subsidiary_detail_department_role_binding_flow(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))

    resp = client.get(f"/subsidiaries/{sub.id}")
    assert resp.status_code == 200
    assert sub.display_name in resp.text

    resp = client.post(f"/subsidiaries/{sub.id}/departments", data={"code": "ops", "display_name": "Operations"}, follow_redirects=False)
    assert resp.status_code == 303
    dept = session.scalar(select(db.Department).where(db.Department.subsidiary_id == sub.id, db.Department.code == "ops"))
    assert dept is not None

    resp = client.post(f"/subsidiaries/{sub.id}/roles", data={"code": "staff", "display_name": "Staff Network"}, follow_redirects=False)
    assert resp.status_code == 303
    role = session.scalar(select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub.id, db.NetworkRole.code == "staff"))
    assert role is not None

    resp = client.post(f"/subsidiaries/{sub.id}/departments/{dept.id}/link-role", data={"role_id": role.id}, follow_redirects=False)
    assert resp.status_code == 303
    link = session.scalar(
        select(db.DepartmentRole).where(db.DepartmentRole.department_id == dept.id, db.DepartmentRole.network_role_id == role.id)
    )
    assert link is not None

    resp = client.post("/sites", data={"name": "Branch1", "radius_cn": "radius-branch1"})
    site = session.scalar(select(db.Site).where(db.Site.radius_cn == "radius-branch1"))
    assert site is not None

    resp = client.post(f"/subsidiaries/{sub.id}/sites/{site.id}/authorize", follow_redirects=False)
    assert resp.status_code == 303
    site_sub = session.scalar(
        select(db.SiteSubsidiary).where(db.SiteSubsidiary.site_id == site.id, db.SiteSubsidiary.subsidiary_id == sub.id)
    )
    assert site_sub is not None
    assert site_sub.is_active is True

    resp = client.get(f"/subsidiaries/{sub.id}")
    assert "Authorized" in resp.text

    resp = client.post(
        f"/subsidiaries/{sub.id}/bindings",
        data={"site_id": site.id, "role_id": role.id, "vlan_id": "50", "fallback_vlan_id": "99"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    binding = session.scalar(
        select(db.SiteRoleBinding).where(db.SiteRoleBinding.site_id == site.id, db.SiteRoleBinding.network_role_id == role.id)
    )
    assert binding is not None
    assert binding.vlan_id == 50
    assert binding.fallback_vlan_id == 99

    resp = client.get(f"/subsidiaries/{sub.id}")
    assert "50" in resp.text

    resp = client.post(f"/subsidiaries/{sub.id}/sites/{site.id}/deauthorize", follow_redirects=False)
    assert resp.status_code == 303
    session.refresh(site_sub)
    assert site_sub.is_active is False


def test_subsidiary_rename_and_delete_flow(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)

    client.post("/subsidiaries", data={"code": "acme", "display_name": "Acme Corp"})
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "acme"))
    assert sub is not None

    resp = client.post(f"/subsidiaries/{sub.id}/rename", data={"display_name": "Acme Renamed"}, follow_redirects=False)
    assert resp.status_code == 303
    session.refresh(sub)
    assert sub.display_name == "Acme Renamed"

    resp = client.get(f"/subsidiaries/{sub.id}")
    assert "Acme Renamed" in resp.text

    resp = client.post(f"/subsidiaries/{sub.id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    fresh = db.make_session_factory(engine)()
    assert fresh.get(db.Subsidiary, sub.id) is None


def test_department_and_role_delete_blocked_then_allowed(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch)
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))

    client.post(f"/subsidiaries/{sub.id}/departments", data={"code": "legal", "display_name": "Legal"})
    dept = session.scalar(select(db.Department).where(db.Department.subsidiary_id == sub.id, db.Department.code == "legal"))
    client.post(f"/subsidiaries/{sub.id}/roles", data={"code": "legalnet", "display_name": "Legal Network"})
    role = session.scalar(select(db.NetworkRole).where(db.NetworkRole.subsidiary_id == sub.id, db.NetworkRole.code == "legalnet"))

    client.post(f"/subsidiaries/{sub.id}/departments/{dept.id}/link-role", data={"role_id": role.id})

    resp = client.post(f"/subsidiaries/{sub.id}/departments/{dept.id}/unlink-role/{role.id}", follow_redirects=False)
    assert resp.status_code == 303
    assert session.scalar(
        select(db.DepartmentRole).where(db.DepartmentRole.department_id == dept.id, db.DepartmentRole.network_role_id == role.id)
    ) is None

    resp = client.post(f"/subsidiaries/{sub.id}/roles/{role.id}/rename", data={"display_name": "Legal Net 2"}, follow_redirects=False)
    assert resp.status_code == 303
    session.refresh(role)
    assert role.display_name == "Legal Net 2"

    resp = client.post(f"/subsidiaries/{sub.id}/departments/{dept.id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    fresh = db.make_session_factory(engine)()
    assert fresh.get(db.Department, dept.id) is None

    resp = client.post(f"/subsidiaries/{sub.id}/roles/{role.id}/delete", follow_redirects=False)
    assert resp.status_code == 303
    fresh2 = db.make_session_factory(engine)()
    assert fresh2.get(db.NetworkRole, role.id) is None


def test_regular_admin_cannot_access_subsidiaries_ui(app_settings, throwaway_pki, monkeypatch):
    client = _client(app_settings, throwaway_pki, monkeypatch, role=db.AdminRole.admin, username="regular-admin")
    assert client.get("/subsidiaries").status_code == 403
    assert client.post("/subsidiaries", data={"code": "x", "display_name": "X"}).status_code == 403
