"""Per-subsidiary admin scoping — an admin with subsidiary_scope set can
only see/manage certs for that one company. Route-level tests use the
real HTTP layer (TestClient) since scoping is enforced at the route
layer, not in cert_service."""

import datetime
import uuid

from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki
from app.main import create_app


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


def _login(client, app_settings, admin):
    cookie = auth._serializer(app_settings.secret_key).dumps(
        {"sub": admin.id, "tv": admin.token_version, "session_start": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    )
    client.cookies.set(auth.SESSION_COOKIE, cookie)


def test_scoped_admin_only_sees_own_subsidiary_in_list_and_export(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    unscoped = _seed_admin(app_settings, "unscoped-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, unscoped)

    client.post("/certs/issue", data={"cn": "boracay-device", "request_id": str(uuid.uuid4()), "subsidiary": "Lezzgo Boracay"})
    client.post("/certs/issue", data={"cn": "cebu-device", "request_id": str(uuid.uuid4()), "subsidiary": "Lezzgo Cebu"})

    scoped = _seed_admin(app_settings, "boracay-admin", db.AdminRole.admin, subsidiary_scope="Lezzgo Boracay")
    _login(client, app_settings, scoped)

    resp = client.get("/certs")
    assert "boracay-device" in resp.text
    assert "cebu-device" not in resp.text

    # a subsidiary filter param that doesn't match their scope is ignored,
    # not honored — scope always wins over whatever's in the query string
    resp2 = client.get("/certs", params={"subsidiary": "Lezzgo Cebu"})
    assert "cebu-device" not in resp2.text

    export_resp = client.get("/certs/export.csv")
    assert "boracay-device" in export_resp.text
    assert "cebu-device" not in export_resp.text


def test_scoped_admin_cannot_view_or_act_on_other_subsidiary_cert(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    unscoped = _seed_admin(app_settings, "unscoped-admin2", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, unscoped)

    client.post("/certs/issue", data={"cn": "cebu-only-device", "request_id": str(uuid.uuid4()), "subsidiary": "Lezzgo Cebu"})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="cebu-only-device").one()

    scoped = _seed_admin(app_settings, "boracay-admin2", db.AdminRole.super_admin, subsidiary_scope="Lezzgo Boracay")
    _login(client, app_settings, scoped)

    assert client.get(f"/certs/{cert.serial}").status_code == 403
    assert client.get(f"/certs/{cert.serial}/bundle").status_code in (403, 410)
    assert client.post(f"/certs/{cert.serial}/suspend", data={"reason": "x"}).status_code == 403
    assert client.post(f"/certs/{cert.serial}/revoke", data={"reason": "x"}).status_code == 403
    assert client.post(f"/certs/{cert.serial}/unsuspend").status_code == 403
    assert client.post(f"/certs/{cert.serial}/reissue").status_code == 403

    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="cebu-only-device").one().status == db.CertStatus.active


def test_scoped_admin_issued_cert_is_forced_to_their_subsidiary(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    scoped = _seed_admin(app_settings, "boracay-issuer", db.AdminRole.admin, subsidiary_scope="Lezzgo Boracay")

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, scoped)

    # trying to issue for a different subsidiary via a hand-crafted
    # request is silently overridden, not honored or rejected
    client.post("/certs/issue", data={
        "cn": "sneaky-device", "request_id": str(uuid.uuid4()), "subsidiary": "Lezzgo Cebu",
    })

    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="sneaky-device").one()
    assert cert.subsidiary == "Lezzgo Boracay"


def test_scoped_admin_bulk_action_skips_out_of_scope_serial(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    unscoped = _seed_admin(app_settings, "unscoped-admin3", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, unscoped)

    client.post("/certs/issue", data={"cn": "cebu-bulk-target", "request_id": str(uuid.uuid4()), "subsidiary": "Lezzgo Cebu"})
    session = db.make_session_factory(db.make_engine(str(app_settings.db_path)))()
    cert = session.query(db.Certificate).filter_by(cn="cebu-bulk-target").one()

    scoped = _seed_admin(app_settings, "boracay-bulk-admin", db.AdminRole.super_admin, subsidiary_scope="Lezzgo Boracay")
    _login(client, app_settings, scoped)

    resp = client.post("/certs/bulk-action", data={"action": "suspend", "serials": [cert.serial]}, follow_redirects=False)
    assert resp.status_code == 303
    assert "0 certificates suspended" in resp.headers["location"] or "flash=" in resp.headers["location"]

    session.expire_all()
    assert session.query(db.Certificate).filter_by(cn="cebu-bulk-target").one().status == db.CertStatus.active


def test_scoped_admin_blocked_from_bulk_issue_and_activity_log(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    scoped = _seed_admin(app_settings, "boracay-restricted", db.AdminRole.super_admin, subsidiary_scope="Lezzgo Boracay")

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, scoped)

    assert client.get("/certs/bulk").status_code == 403
    assert client.post("/certs/bulk/preview", data={"identifiers_text": "a\nb"}).status_code == 403
    assert client.get("/activity").status_code == 403


def test_unscoped_admin_is_unaffected(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings, "plain-admin", db.AdminRole.super_admin)

    app = create_app(app_settings)
    client = TestClient(app)
    _login(client, app_settings, admin)

    client.post("/certs/issue", data={"cn": "unscoped-device", "request_id": str(uuid.uuid4()), "subsidiary": "Bay Mall"})
    resp = client.get("/certs")
    assert "unscoped-device" in resp.text
    assert client.get("/certs/bulk").status_code == 200
    assert client.get("/activity").status_code == 200
