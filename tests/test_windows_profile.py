"""Tests for Windows 802.1X XML Wi-Fi profile generator and endpoints."""

from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes

from app import auth, crl_push, db, pki, windows_profile
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username="win-admin", role=db.AdminRole.super_admin):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username=username, password_hash=auth.hash_password("correcthorse123"), role=role)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_generate_windows_wifi_xml_structure(throwaway_pki):
    xml_str = windows_profile.generate_windows_wifi_xml(
        ssid="Test-Corp-WiFi",
        ca_cert=throwaway_pki["inter_cert"],
        non_broadcast=True,
        server_names="radius.corp.example.com",
    )
    assert isinstance(xml_str, str)
    root = ET.fromstring(xml_str)
    assert "WLANProfile" in root.tag

    # Verify SHA-1 thumbprint matches CA
    ca_fp = throwaway_pki["inter_cert"].fingerprint(hashes.SHA1()).hex().lower()
    expected_thumbprint = " ".join(ca_fp[i : i + 2] for i in range(0, len(ca_fp), 2))
    assert expected_thumbprint in xml_str

    # Verify EAP-TLS Type 13
    assert "<Type>13</Type>" in xml_str or "<Type xmlns=\"http://www.microsoft.com/provisioning/EapCommon\">13</Type>" in xml_str
    assert "Test-Corp-WiFi" in xml_str
    assert "<nonBroadcast>true</nonBroadcast>" in xml_str
    assert "<ServerNames>radius.corp.example.com</ServerNames>" in xml_str


def test_windows_profile_web_endpoint_and_bundle_preservation(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    # Issue a cert via standard issue endpoint
    issue_resp = client.post(
        "/api/certs",
        json={"cn": "bob.windows", "request_id": str(uuid.uuid4())},
    )
    assert issue_resp.status_code == 201
    serial = str(issue_resp.json()["serial"])

    # Download Windows Profile XML
    resp = client.get(f"/certs/{serial}/windows-profile")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-wifi-config")
    assert "Profile.xml" in resp.headers.get("content-disposition", "")
    assert "Corporate-WiFi" in resp.text
    assert "<Type" in resp.text

    # Verify downloading windows-profile does NOT consume the pending .p12 bundle!
    p12_resp = client.get(f"/certs/{serial}/bundle")
    assert p12_resp.status_code == 200
    assert p12_resp.headers["content-type"] == "application/x-pkcs12"

    # Now the .p12 bundle is consumed; bundle endpoint returns 410 Gone
    p12_resp2 = client.get(f"/certs/{serial}/bundle")
    assert p12_resp2.status_code == 410

    # But windows-profile XML can still be retrieved anytime!
    win_resp2 = client.get(f"/certs/{serial}/windows-profile")
    assert win_resp2.status_code == 200


def test_windows_profile_api_endpoint(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    # Issue via API
    issue_resp = client.post(
        "/api/certs",
        json={"cn": "api.win.user", "request_id": str(uuid.uuid4())},
    )
    assert issue_resp.status_code == 201
    serial = str(issue_resp.json()["serial"])

    # Fetch Windows profile via API
    resp = client.get(f"/api/certs/{serial}/windows-profile")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-wifi-config")
    assert "Corporate-WiFi" in resp.text

    # 404 for unknown serial
    bad_resp = client.get("/api/certs/nonexistent123/windows-profile")
    assert bad_resp.status_code == 404
