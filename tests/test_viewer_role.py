"""Read-only role (HANDOFF-COMPLIANCE.md §3) — a viewer can see the cert
list, detail pages, activity log and dashboard, but every mutating route
plus bundle download and export must reject it with 403. Enumerates the
app's actual routes rather than hand-listing them, so a future route that
forgets to opt into require_write fails this test instead of silently
shipping a hole.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app import auth, crl_push, db, pki
from app.main import create_app
from tests.conftest import login_as

# Routes that mutate state, or hand back a bundle/export, but are exempt
# from the viewer-must-get-403 sweep below because they're not gated on
# an admin session at all (site-agent auth, unauthenticated login/logout/
# ping) or they act on the caller's OWN account rather than certs/sites/
# admins (password change, ending one's own session) — HANDOFF-COMPLIANCE
# §3 only excludes cert/admin/site management from viewer, not self-service.
_EXEMPT = {
    ("POST", "/api/site/checkin"),
    ("POST", "/api/site/server-cert/renew"),
    ("POST", "/auth/login"),
    ("POST", "/auth/logout"),
    ("POST", auth.PASSWORD_CHANGE_PATH),
    ("POST", "/account/sessions/{session_id}/revoke"),
}

# path -> kwargs for client.request(), so a route with required
# Form/body fields doesn't 422 before its auth dependency ever runs.
_PAYLOADS = {
    ("POST", "/api/certs"): {"json": {"cn": "device-x", "request_id": str(uuid.uuid4())}},
    ("POST", "/api/certs/{serial}/suspend"): {"json": {"reason": "test"}},
    ("POST", "/certs/issue"): {"data": {"cn": "device-x", "request_id": str(uuid.uuid4())}},
    ("POST", "/certs/bulk-action"): {"data": {"serials": ["nonexistent"], "action": "suspend"}},
    ("POST", "/certs/bulk/{batch_token}/fix-row"): {"data": {"row_index": "0", "identifier": "device-x"}},
    ("POST", "/certs/bulk/confirm"): {"data": {"batch_token": "nonexistent", "export_password": "x" * 12}},
    ("POST", "/api/admin/sites"): {"json": {"name": "x", "radius_cn": "x"}},
    ("POST", "/admins"): {"data": {"username": "x", "role": "admin"}},
    ("POST", "/employees/{employee_key}/offboard"): {"data": {"confirm_name": "x"}},
}


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_viewer(app_settings, username="viewer-1"):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(
        username=username, password_hash=auth.hash_password("correcthorse123"),
        role=db.AdminRole.viewer,
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def _iter_routes(routes):
    for route in routes:
        # Newer Starlette wraps each include_router() call in an
        # _IncludedRouter whose real APIRouter (with the actual route
        # list) lives at .original_router — recurse into it, and into
        # any plain nested router, so this sees every leaf route.
        sub = getattr(route, "original_router", None) or getattr(route, "routes", None)
        if sub is not None:
            yield from _iter_routes(getattr(sub, "routes", sub))
        else:
            yield route


def _mutating_routes(app):
    routes = []
    for route in _iter_routes(app.routes):
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", None)
        if path is None:
            continue
        for method in methods - {"HEAD", "OPTIONS", "GET"}:
            routes.append((method, path))
    return routes


@pytest.fixture
def viewer_client(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    viewer = _seed_viewer(app_settings)
    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, viewer)
    return client, app


def test_every_mutating_route_rejects_viewer(viewer_client):
    client, app = viewer_client
    routes = _mutating_routes(app)
    assert routes, "route enumeration returned nothing — something's broken in the sweep itself"

    failures = []
    for method, path in routes:
        if (method, path) in _EXEMPT:
            continue
        url = path.format(
            serial="nonexistent", batch_token="nonexistent", batch_id="nonexistent",
            site_id="nonexistent", admin_id="nonexistent", session_id="nonexistent",
            token="nonexistent", employee_key="nonexistent",
        )
        kwargs = _PAYLOADS.get((method, path), {})
        resp = client.request(method, url, **kwargs)
        if resp.status_code != 403:
            failures.append((method, path, resp.status_code))

    assert not failures, f"routes that should reject viewer with 403 but didn't: {failures}"


def test_bundle_and_export_routes_reject_viewer(viewer_client):
    client, _ = viewer_client
    for method, path in [
        ("GET", "/api/certs/nonexistent/bundle"),
        ("GET", "/certs/nonexistent/bundle"),
        ("GET", "/certs/nonexistent/delivery"),
        ("GET", "/certs/export.csv"),
        ("GET", "/api/batches/nonexistent/bundle"),
    ]:
        resp = client.request(method, path)
        assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}"


def test_viewer_can_still_view(viewer_client):
    client, _ = viewer_client
    for path in ["/dashboard", "/certs", "/activity"]:
        resp = client.get(path)
        assert resp.status_code == 200, f"GET {path} -> {resp.status_code}"


def test_subsidiary_scope_applies_to_viewer(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed"))
    _write_throwaway_pki(app_settings, throwaway_pki)
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    scoped_viewer = db.Admin(
        username="scoped-viewer", password_hash=auth.hash_password("correcthorse123"),
        role=db.AdminRole.viewer, subsidiary_scope=db.SUBSIDIARIES[0],
    )
    session.add(scoped_viewer)
    session.commit()
    session.refresh(scoped_viewer)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, scoped_viewer)
    resp = client.get("/certs")
    assert resp.status_code == 200
