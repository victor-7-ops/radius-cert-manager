"""Bulk "renew" — reissue a whole selection of certs at once (e.g.
everything expiring soon) from the cert list's bulk action bar, instead
of one at a time from each cert's detail page. Same coexistence rule as
a single reissue: the old cert isn't touched, only linked via
supersedes_id."""

import uuid

from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username, role, subsidiary_scope=None):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username=username, password_hash=auth.hash_password("correcthorse123"),
        role=role, subsidiary_scope=subsidiary_scope,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_bulk_renew_reissues_all_selected_and_leaves_old_certs_active(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "renew-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "renew-a", "request_id": str(uuid.uuid4()), "employee_name": "Jordan Ellis"})
    client.post("/certs/issue", data={"cn": "renew-b", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    old_a = session.query(db.Certificate).filter_by(cn="renew-a").one()
    old_b = session.query(db.Certificate).filter_by(cn="renew-b").one()

    resp = client.post("/certs/bulk-action", data={
        "action": "renew",
        "export_password": "SharedRenewPassword123",
        "serials": [old_a.serial, old_b.serial],
    }, follow_redirects=False)
    assert resp.status_code == 303
    assert "/certs/bulk/" in resp.headers["location"]

    result_resp = client.get(resp.headers["location"])
    assert result_resp.status_code == 200
    assert "2 succeeded" in result_resp.text
    assert "renew-a" in result_resp.text
    assert "renew-b" in result_resp.text

    session.expire_all()
    # old certs untouched
    assert session.query(db.Certificate).filter_by(id=old_a.id).one().status == db.CertStatus.active
    assert session.query(db.Certificate).filter_by(id=old_b.id).one().status == db.CertStatus.active
    # new certs exist, linked, device info carried over
    rows_a = session.query(db.Certificate).filter_by(cn="renew-a").all()
    assert len(rows_a) == 2
    new_a = [r for r in rows_a if r.id != old_a.id][0]
    assert new_a.supersedes_id == old_a.id
    assert new_a.employee_name == "Jordan Ellis"


def test_bulk_renew_bundle_download_has_both_p12s(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "renew-zip-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "renew-zip-a", "request_id": str(uuid.uuid4())})
    client.post("/certs/issue", data={"cn": "renew-zip-b", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    a = session.query(db.Certificate).filter_by(cn="renew-zip-a").one()
    b = session.query(db.Certificate).filter_by(cn="renew-zip-b").one()

    resp = client.post("/certs/bulk-action", data={
        "action": "renew", "export_password": "SharedRenewPassword123", "serials": [a.serial, b.serial],
    }, follow_redirects=False)
    batch_id = resp.headers["location"].rsplit("/", 1)[-1]

    import io
    import zipfile
    zip_resp = client.get(f"/api/batches/{batch_id}/bundle")
    assert zip_resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(zip_resp.content))
    names = zf.namelist()
    assert "renew-zip-a.p12" in names
    assert "renew-zip-b.p12" in names
    assert "manifest.csv" in names
    manifest = zf.read("manifest.csv").decode()
    assert "SharedRenewPassword123" not in manifest


def test_bulk_renew_rejects_short_export_password(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "renew-short-admin", db.AdminRole.admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "renew-short-a", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="renew-short-a").one()

    resp = client.post("/certs/bulk-action", data={
        "action": "renew", "export_password": "short", "serials": [cert.serial],
    })
    assert resp.status_code == 400

    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="renew-short-a").count() == 1  # nothing issued


def test_bulk_renew_partial_failure_does_not_block_the_rest(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "renew-partial-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "renew-ok", "request_id": str(uuid.uuid4())})
    client.post("/certs/issue", data={"cn": "renew-revoked", "request_id": str(uuid.uuid4())})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    ok_cert = session.query(db.Certificate).filter_by(cn="renew-ok").one()
    revoked_cert = session.query(db.Certificate).filter_by(cn="renew-revoked").one()
    client.post(f"/certs/{revoked_cert.serial}/revoke", data={"reason": "test"})

    resp = client.post("/certs/bulk-action", data={
        "action": "renew", "export_password": "SharedRenewPassword123",
        "serials": [ok_cert.serial, revoked_cert.serial],
    }, follow_redirects=False)
    result_resp = client.get(resp.headers["location"])
    assert "1 succeeded" in result_resp.text
    assert "1 failed" in result_resp.text
    assert "renew-ok" in result_resp.text


def test_bulk_renew_requires_min_password_and_scope(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    unscoped = _seed_admin(app_settings, "renew-scope-unscoped", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, unscoped)

    client.post("/certs/issue", data={"cn": "renew-scope-target", "request_id": str(uuid.uuid4()), "subsidiary": "Lezzgo Cebu"})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="renew-scope-target").one()

    scoped = _seed_admin(app_settings, "renew-scope-boracay", db.AdminRole.super_admin, subsidiary_scope="Lezzgo Boracay")
    login_as(client, app_settings, scoped)

    resp = client.post("/certs/bulk-action", data={
        "action": "renew", "export_password": "SharedRenewPassword123", "serials": [cert.serial],
    }, follow_redirects=False)
    assert resp.status_code == 303  # batch created, but...
    result_resp = client.get(resp.headers["location"])
    assert "0 succeeded" in result_resp.text  # ...out-of-scope cert silently skipped

    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="renew-scope-target").count() == 1  # no new cert made
