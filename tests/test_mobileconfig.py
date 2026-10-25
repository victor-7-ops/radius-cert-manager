import plistlib
import uuid

import pytest
from fastapi.testclient import TestClient

from app import auth, crl_push, db, mobileconfig, pki
from app.main import create_app
from tests.conftest import login_as


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def _seed_admin(app_settings, username="mc-admin", role=db.AdminRole.super_admin):
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username=username, password_hash=auth.hash_password("correcthorse123"), role=role)
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin


def test_generate_mobileconfig_payload_structure(throwaway_pki):
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "alice.smith")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=30
    )
    bundle = pki.build_pkcs12(
        "alice.smith", key, cert, [throwaway_pki["inter_cert"]], password="test-export-password"
    )

    xml_data = mobileconfig.generate_mobileconfig(
        cn="alice.smith",
        serial=serial,
        pkcs12_data=bundle.data,
        ca_cert=throwaway_pki["inter_cert"],
        wifi_ssid="Acme-Corp-WiFi",
        export_password="test-export-password",
        organization="Acme Corporation",
    )

    assert isinstance(xml_data, bytes)
    parsed = plistlib.loads(xml_data)

    # Top-level checks
    assert parsed["PayloadType"] == "Configuration"
    assert parsed["PayloadVersion"] == 1
    assert parsed["PayloadOrganization"] == "Acme Corporation"
    assert "alice.smith" in parsed["PayloadDisplayName"]
    assert "Acme-Corp-WiFi" in parsed["PayloadDisplayName"]

    # Content payloads: CA anchor, identity PKCS#12, Wi-Fi managed
    payloads = parsed["PayloadContent"]
    assert len(payloads) == 3

    # Payload 1: CA Certificate
    ca_payload = payloads[0]
    assert ca_payload["PayloadType"] == "com.apple.security.pkcs1"
    ca_uuid = ca_payload["PayloadUUID"]
    assert len(ca_payload["PayloadContent"]) > 0

    # Payload 2: Client PKCS#12
    id_payload = payloads[1]
    assert id_payload["PayloadType"] == "com.apple.security.pkcs12"
    id_uuid = id_payload["PayloadUUID"]
    assert id_payload["Password"] == "test-export-password"
    assert id_payload["PayloadContent"] == bundle.data

    # Payload 3: Wi-Fi Managed Network
    wifi_payload = payloads[2]
    assert wifi_payload["PayloadType"] == "com.apple.wifi.managed"
    assert wifi_payload["SSID_STR"] == "Acme-Corp-WiFi"
    assert wifi_payload["EncryptionType"] == "WPA2"
    assert wifi_payload["AutoJoin"] is True
    assert wifi_payload["PayloadCertificateUUID"] == id_uuid

    eap_cfg = wifi_payload["EAPClientConfiguration"]
    assert eap_cfg["AcceptEAPTypes"] == [13]  # EAP-TLS
    assert eap_cfg["PayloadCertificateAnchorUUID"] == [ca_uuid]
    assert eap_cfg["UserIdentities"] == ["alice.smith"]


def test_mobileconfig_web_and_qr_download(app_settings, throwaway_pki, monkeypatch):
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
        json={"cn": "bob.jones", "request_id": str(uuid.uuid4())},
    )
    assert issue_resp.status_code == 201
    serial = str(issue_resp.json()["serial"])

    # Download mobileconfig via web endpoint
    resp = client.get(f"/certs/{serial}/mobileconfig")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-apple-as-config"
    assert 'filename="bob.jones.mobileconfig"' in resp.headers.get("content-disposition", "")
    parsed = plistlib.loads(resp.content)
    assert parsed["PayloadType"] == "Configuration"

    # Second download returns 410 (single-use semantics preserved)
    resp2 = client.get(f"/certs/{serial}/mobileconfig")
    assert resp2.status_code == 410


def test_mobileconfig_qr_anonymous_download(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)

    app = create_app(app_settings)
    auth_client = TestClient(app)
    login_as(auth_client, app_settings, admin)

    # Issue a cert
    issue_resp = auth_client.post(
        "/api/certs",
        json={"cn": "carol.white", "request_id": str(uuid.uuid4())},
    )
    assert issue_resp.status_code == 201
    serial = str(issue_resp.json()["serial"])

    # Generate QR token
    token = auth.make_bundle_qr_token(app_settings.secret_key, serial)

    # Anonymous client can download via QR link
    anon_client = TestClient(app)
    anon_resp = anon_client.get(f"/certs/{serial}/mobileconfig/qr", params={"token": token})
    assert anon_resp.status_code == 200
    assert anon_resp.headers["content-type"] == "application/x-apple-as-config"

    # Consumed once — subsequent request is 410
    anon_resp2 = anon_client.get(f"/certs/{serial}/mobileconfig/qr", params={"token": token})
    assert anon_resp2.status_code == 410


def test_mobileconfig_api_endpoint(app_settings, throwaway_pki, monkeypatch):
    monkeypatch.setattr(
        crl_push, "push_crl", lambda *a, **k: crl_push.PushResult(ok=True, detail="stubbed")
    )
    _write_throwaway_pki(app_settings, throwaway_pki)
    admin = _seed_admin(app_settings)

    app = create_app(app_settings)
    client = TestClient(app)
    login_as(client, app_settings, admin)

    issue_resp = client.post(
        "/api/certs",
        json={"cn": "dave.miller", "request_id": str(uuid.uuid4())},
    )
    assert issue_resp.status_code == 201
    serial = str(issue_resp.json()["serial"])

    resp = client.get(f"/api/certs/{serial}/mobileconfig")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-apple-as-config"
    parsed = plistlib.loads(resp.content)
    assert parsed["PayloadType"] == "Configuration"

    # Consumed
    resp2 = client.get(f"/api/certs/{serial}/mobileconfig")
    assert resp2.status_code == 410
