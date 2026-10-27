"""Tests for signed site policy compilation, synchronization, and verification.

Implements B05 test specifications:
- Ed25519 key generation and round-trip verification
- Monotonic revisioning and canonical deterministic JSON encoding
- Rejection of tampered payloads, wrong keys, wrong sites, expired leases, and replay attacks
- Duplicate JSON key rejection
- Agent-facing endpoints: GET /api/site/network-policy and POST /api/site/network-policy/ack
"""

import base64
import datetime
import hashlib
import json
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auth, db, pki, site_policy
from app.main import create_app


@pytest.fixture
def site_test_setup(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))
    assert sub

    role_staff = db.NetworkRole(
        subsidiary_id=sub.id,
        code="staff",
        display_name="Staff Network",
        is_active=True,
    )
    role_guest = db.NetworkRole(
        subsidiary_id=sub.id,
        code="guest",
        display_name="Guest Network",
        is_active=False,
    )
    session.add_all([role_staff, role_guest])
    session.flush()

    token = "site-secret-token-12345"
    token_hash = auth.hash_password(token)

    site = db.Site(
        id="site-boracay-station1",
        name="Boracay Station 1",
        radius_cn="boracay-st1.example.local",
        auth_token_hash=token_hash,
    )
    session.add(site)
    session.flush()
    session.add(db.SiteSubsidiary(site_id=site.id, subsidiary_id=sub.id, is_active=True))

    binding_staff = db.SiteRoleBinding(
        site_id=site.id,
        subsidiary_id=sub.id,
        network_role_id=role_staff.id,
        vlan_id=100,
        fallback_vlan_id=999,
        platform_enabled=True,
        tenant_enabled=True,
        config_revision=1,
    )
    binding_guest = db.SiteRoleBinding(
        site_id=site.id,
        subsidiary_id=sub.id,
        network_role_id=role_guest.id,
        vlan_id=200,
        fallback_vlan_id=999,
        platform_enabled=True,
        tenant_enabled=False,
        config_revision=1,
    )
    session.add_all([binding_staff, binding_guest])
    session.commit()

    priv_key, pub_key = site_policy.get_or_create_policy_signing_key(app_settings.pki_path)

    app = create_app(app_settings)
    client = TestClient(app)

    return {
        "client": client,
        "session": session,
        "site": site,
        "token": token,
        "sub": sub,
        "role_staff": role_staff,
        "role_guest": role_guest,
        "priv_key": priv_key,
        "pub_key": pub_key,
        "app_settings": app_settings,
    }


def test_ed25519_key_export_and_load(tmp_path):
    priv, key_id = site_policy.generate_policy_signing_key()
    pub = priv.public_key()

    priv_pem = site_policy.export_private_key_pem(priv)
    pub_pem = site_policy.export_public_key_pem(pub)

    loaded_priv = site_policy.load_private_key_pem(priv_pem)
    loaded_pub = site_policy.load_public_key_pem(pub_pem)

    assert site_policy.get_public_key_id(pub) == key_id
    assert site_policy.get_public_key_id(loaded_pub) == key_id


def test_sign_verify_code_bundle_roundtrip():
    priv, _ = site_policy.generate_policy_signing_key()
    pub = priv.public_key()
    content = b"print('hello from the radius adapter')\n"

    envelope = site_policy.sign_code_bundle(content, version="abc123", private_key=priv)
    payload = site_policy.verify_code_bundle_envelope(envelope, pub)

    assert payload["type"] == "radius_adapter"
    assert payload["version"] == "abc123"
    assert payload["content_bytes"] == content
    assert payload["sha256"] == hashlib.sha256(content).hexdigest()


def test_verify_code_bundle_rejects_wrong_key():
    priv, _ = site_policy.generate_policy_signing_key()
    other_priv, _ = site_policy.generate_policy_signing_key()
    envelope = site_policy.sign_code_bundle(b"content", version="v1", private_key=priv)

    with pytest.raises(site_policy.PolicySignatureError):
        site_policy.verify_code_bundle_envelope(envelope, other_priv.public_key())


def test_verify_code_bundle_rejects_tampered_content():
    priv, _ = site_policy.generate_policy_signing_key()
    envelope = site_policy.sign_code_bundle(b"original", version="v1", private_key=priv)

    tampered_payload = json.loads(base64.b64decode(envelope["payload_base64"]))
    tampered_payload["content_base64"] = base64.b64encode(b"malicious").decode("ascii")
    envelope["payload_base64"] = base64.b64encode(
        json.dumps(tampered_payload).encode("utf-8")
    ).decode("ascii")

    with pytest.raises(site_policy.PolicySignatureError):
        site_policy.verify_code_bundle_envelope(envelope, priv.public_key())


def test_compile_sign_verify_envelope(site_test_setup):
    s = site_test_setup
    payload = site_policy.compile_site_policy(
        s["site"],
        s["session"],
        revision=1,
        lease_hours=24,
    )
    assert payload["schema_version"] == 2
    assert payload["site_id"] == s["site"].id
    assert payload["revision"] == 1
    assert len(payload["bindings"]) == 2

    envelope = site_policy.sign_policy_payload(payload, s["priv_key"])
    assert "payload_base64" in envelope
    assert "signature_base64" in envelope
    assert "signing_key_id" in envelope

    # Verify succeeds
    verified = site_policy.verify_policy_envelope(
        envelope,
        s["pub_key"],
        expected_site_id=s["site"].id,
        min_revision=1,
    )
    assert verified["site_id"] == s["site"].id
    assert verified["revision"] == 1
    assert len(verified["bindings"]) == 2


def test_verify_envelope_rejections(site_test_setup):
    s = site_test_setup
    payload = site_policy.compile_site_policy(s["site"], s["session"], revision=5)
    envelope = site_policy.sign_policy_payload(payload, s["priv_key"])

    # 1. Tampered payload bytes
    tampered_bytes = base64.b64decode(envelope["payload_base64"]).replace(b"100", b"101")
    tampered_envelope = dict(envelope)
    tampered_envelope["payload_base64"] = base64.b64encode(tampered_bytes).decode("ascii")
    with pytest.raises(site_policy.PolicySignatureError):
        site_policy.verify_policy_envelope(tampered_envelope, s["pub_key"], expected_site_id=s["site"].id)

    # 2. Wrong site ID
    with pytest.raises(site_policy.PolicySchemaError, match="does not match expected site"):
        site_policy.verify_policy_envelope(envelope, s["pub_key"], expected_site_id="different-site-id")

    # 3. Replay attack (revision lower than minimum installed)
    with pytest.raises(site_policy.PolicyReplayError, match="lower than minimum expected revision"):
        site_policy.verify_policy_envelope(envelope, s["pub_key"], expected_site_id=s["site"].id, min_revision=6)

    # 4. Wrong public key
    other_priv, _ = site_policy.generate_policy_signing_key()
    with pytest.raises(site_policy.PolicySignatureError, match="Envelope signed by key ID"):
        site_policy.verify_policy_envelope(envelope, other_priv.public_key(), expected_site_id=s["site"].id)

    # 5. Expired lease
    expired_payload = dict(payload)
    expired_payload["expires_at"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat()
    expired_env = site_policy.sign_policy_payload(expired_payload, s["priv_key"])
    with pytest.raises(site_policy.PolicyExpiredError, match="Policy lease expired"):
        site_policy.verify_policy_envelope(expired_env, s["pub_key"], expected_site_id=s["site"].id)


def test_duplicate_json_keys_rejected():
    duplicate_json = b'{"schema_version":2,"site_id":"s1","revision":1,"site_id":"s2"}'
    with pytest.raises(site_policy.PolicySchemaError, match="Duplicate key in JSON payload"):
        site_policy.parse_canonical_json(duplicate_json)


def test_compile_policy_empty_site_allowlist_withdraws_all_bindings(site_test_setup):
    s = site_test_setup
    memberships = s["session"].scalars(
        select(db.SiteSubsidiary).where(db.SiteSubsidiary.site_id == s["site"].id)
    ).all()
    for membership in memberships:
        membership.is_active = False
    s["session"].commit()

    payload = site_policy.compile_site_policy(s["site"], s["session"], revision=2)
    assert payload["bindings"] == []


def test_site_network_policy_api_and_ack(site_test_setup):
    s = site_test_setup
    client = s["client"]
    token = s["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Pull network policy
    resp = client.get("/api/site/network-policy", headers=headers)
    assert resp.status_code == 200
    etag = resp.headers.get("ETag")
    assert etag
    envelope = resp.json()

    # Verify signature
    verified = site_policy.verify_policy_envelope(
        envelope,
        s["pub_key"],
        expected_site_id=s["site"].id,
    )
    assert verified["site_id"] == s["site"].id
    assert verified["revision"] >= 1

    # 2. Pull with If-None-Match gives 304 Not Modified
    resp_304 = client.get("/api/site/network-policy", headers={**headers, "If-None-Match": etag})
    assert resp_304.status_code == 304

    # 3. Post Acknowledgement
    resp_ack = client.post(
        "/api/site/network-policy/ack",
        headers=headers,
        json={
            "revision": verified["revision"],
            "payload_hash": etag,
            "success": True,
            "detail": "Installed FreeRADIUS policy cleanly",
            "agent_version": "1.0.0",
        },
    )
    assert resp_ack.status_code == 200
    assert resp_ack.json()["ok"] is True
    assert resp_ack.json()["revision"] == verified["revision"]

    # Verify recorded in DB
    ack = s["session"].scalar(
        select(db.SitePolicyAck).where(
            db.SitePolicyAck.site_id == s["site"].id,
            db.SitePolicyAck.revision == verified["revision"],
        )
    )
    assert ack is not None
    assert ack.success is True
    assert "Installed FreeRADIUS policy cleanly" in ack.detail


def test_site_radius_adapter_pull_api(site_test_setup):
    s = site_test_setup
    client = s["client"]
    headers = {"Authorization": f"Bearer {s['token']}"}

    resp = client.get("/api/site/radius-adapter", headers=headers)
    assert resp.status_code == 200
    etag = resp.headers.get("ETag")
    assert etag
    envelope = resp.json()

    payload = site_policy.verify_code_bundle_envelope(envelope, s["pub_key"])
    assert payload["type"] == "radius_adapter"
    assert payload["sha256"] == etag
    # Served content is the hub's own deployed adapter source.
    assert b"def post_auth" in payload["content_bytes"]

    resp_304 = client.get("/api/site/radius-adapter", headers={**headers, "If-None-Match": etag})
    assert resp_304.status_code == 304
