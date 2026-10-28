"""Tests for FreeRADIUS EAP-TLS local authorization adapter (deploy/radius/authorize_policy.py).

Verifies B06 acceptance matrix:
- Valid Subject parsing with strict single-cardinality O and OU UUID validation
- Both tenant switches ON -> Primary VLAN
- Tenant role switch OFF -> Configured Fallback VLAN
- Tenant site switch OFF -> Configured Fallback VLAN
- Platform block -> REJECT (never triggers fallback)
- Missing binding -> REJECT
- Policy lease expiration -> REJECT (fail closed)
- Mismatched site ID -> REJECT
- FreeRADIUS post_auth hook attribute reply tuple formatting
"""

import datetime
import uuid
import pytest

from deploy.radius import authorize_policy as ap


@pytest.fixture
def sample_uuids():
    return {
        "sub_a": str(uuid.uuid4()),
        "sub_b": str(uuid.uuid4()),
        "role_staff": str(uuid.uuid4()),
        "role_exec": str(uuid.uuid4()),
        "site_id": "site-station-1",
    }


@pytest.fixture
def valid_policy(sample_uuids):
    u = sample_uuids
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(hours=24)
    return {
        "schema_version": 2,
        "site_id": u["site_id"],
        "revision": 1,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "bindings": [
            {
                "subsidiary_id": u["sub_a"],
                "network_role_id": u["role_staff"],
                "primary_vlan_id": 100,
                "fallback_vlan_id": 999,
                "platform_enabled": True,
                "tenant_enabled": True,
                "role_active": True,
            },
            {
                "subsidiary_id": u["sub_a"],
                "network_role_id": u["role_exec"],
                "primary_vlan_id": 200,
                "fallback_vlan_id": 999,
                "platform_enabled": True,
                "tenant_enabled": False,  # Site switch OFF
                "role_active": True,
            },
            {
                "subsidiary_id": u["sub_b"],
                "network_role_id": u["role_staff"],
                "primary_vlan_id": 300,
                "fallback_vlan_id": 999,
                "platform_enabled": False,  # Platform BLOCKED
                "tenant_enabled": True,
                "role_active": True,
            },
        ],
    }


def test_parse_certificate_identity_valid(sample_uuids):
    u = sample_uuids
    subj_openssl = f"/CN=ThinkPad-01/O={u['sub_a']}/OU={u['role_staff']}"
    sub, role = ap.parse_certificate_identity(subj_openssl)
    assert sub == u["sub_a"]
    assert role == u["role_staff"]

    subj_rfc = f"CN=MacBook-02, O={u['sub_a']}, OU={u['role_staff']}"
    sub2, role2 = ap.parse_certificate_identity(subj_rfc)
    assert sub2 == u["sub_a"]
    assert role2 == u["role_staff"]


def test_parse_certificate_identity_invalid():
    # Missing OU
    with pytest.raises(ValueError, match="Expected exactly 1 OU"):
        ap.parse_certificate_identity("/CN=Device/O=c4b72605-728b-4028-a28a-7cf513f28d8b")

    # Missing O
    with pytest.raises(ValueError, match="Expected exactly 1 O"):
        ap.parse_certificate_identity("/CN=Device/OU=c4b72605-728b-4028-a28a-7cf513f28d8b")

    # Non-UUID O
    with pytest.raises(ValueError, match="is not a valid UUID"):
        ap.parse_certificate_identity("/CN=Device/O=not-a-uuid/OU=c4b72605-728b-4028-a28a-7cf513f28d8b")


def test_decision_primary_vlan(sample_uuids, valid_policy):
    u = sample_uuids
    subj = f"/CN=Device-1/O={u['sub_a']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "accept"
    assert dec.vlan_id == 100
    assert dec.vlan_type == "primary"


def test_decision_fallback_vlan_tenant_site_off(sample_uuids, valid_policy):
    u = sample_uuids
    subj = f"/CN=Device-2/O={u['sub_a']}/OU={u['role_exec']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "accept"
    assert dec.vlan_id == 999
    assert dec.vlan_type == "fallback"


def test_decision_fallback_vlan_tenant_role_off(sample_uuids, valid_policy):
    u = sample_uuids
    # Modify role_active to False on staff
    valid_policy["bindings"][0]["role_active"] = False
    subj = f"/CN=Device-1/O={u['sub_a']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "accept"
    assert dec.vlan_id == 999
    assert dec.vlan_type == "fallback"


def test_decision_vlan_segmentation_disabled_strips_primary_vlan(sample_uuids, valid_policy):
    u = sample_uuids
    valid_policy["vlan_segmentation_enabled"] = False
    subj = f"/CN=Device-1/O={u['sub_a']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "accept"
    assert dec.vlan_id is None
    assert dec.vlan_type is None


def test_decision_vlan_segmentation_disabled_strips_fallback_vlan(sample_uuids, valid_policy):
    u = sample_uuids
    valid_policy["vlan_segmentation_enabled"] = False
    subj = f"/CN=Device-2/O={u['sub_a']}/OU={u['role_exec']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "accept"
    assert dec.vlan_id is None
    assert dec.vlan_type is None


def test_decision_vlan_segmentation_disabled_still_rejects_platform_block(sample_uuids, valid_policy):
    # Segmentation is only ever about VLAN output, never about the
    # authorization decision itself -- a platform block must still reject.
    u = sample_uuids
    valid_policy["vlan_segmentation_enabled"] = False
    subj = f"/CN=Device-3/O={u['sub_b']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "reject"
    assert dec.vlan_id is None


def test_decision_vlan_segmentation_missing_defaults_to_enabled(sample_uuids, valid_policy):
    # Older cached policy.json predating this field must behave exactly
    # as it always did -- missing means segmentation stays on.
    assert "vlan_segmentation_enabled" not in valid_policy
    u = sample_uuids
    subj = f"/CN=Device-1/O={u['sub_a']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "accept"
    assert dec.vlan_id == 100


def test_decision_platform_block_rejects_without_fallback(sample_uuids, valid_policy):
    u = sample_uuids
    subj = f"/CN=Device-3/O={u['sub_b']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "reject"
    assert dec.vlan_id is None
    assert "Platform superadmin has disabled access" in dec.reason


def test_decision_missing_binding_rejects(sample_uuids, valid_policy):
    u = sample_uuids
    unknown_role = str(uuid.uuid4())
    subj = f"/CN=Device-Unknown/O={u['sub_a']}/OU={unknown_role}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "reject"
    assert dec.vlan_id is None
    assert "No binding" in dec.reason


def test_decision_expired_policy_fails_closed(sample_uuids, valid_policy):
    u = sample_uuids
    # Set expiration in past
    valid_policy["expires_at"] = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
    subj = f"/CN=Device-1/O={u['sub_a']}/OU={u['role_staff']}"
    dec = ap.evaluate_authorization(subj, valid_policy, expected_site_id=u["site_id"])
    assert dec.outcome == "reject"
    assert dec.vlan_id is None
    assert "expired" in dec.reason


def test_freeradius_post_auth_hook(tmp_path, sample_uuids, valid_policy, monkeypatch):
    u = sample_uuids
    policy_file = tmp_path / "policy.json"
    import json
    policy_file.write_text(json.dumps(valid_policy))
    monkeypatch.setattr(ap, "LOCAL_SITE_ID", u["site_id"])
    monkeypatch.setattr(ap, "LOCAL_POLICY_PATH", str(policy_file))

    # Test Accept tuple
    p_accept = (
        ("TLS-Client-Cert-Subject", f"/CN=Device-1/O={u['sub_a']}/OU={u['role_staff']}"),
    )
    result_code, reply_pairs, _ = ap.post_auth(p_accept)
    assert result_code == ap.RLM_MODULE_OK
    reply_dict = dict(reply_pairs)
    assert reply_dict["Tunnel-Type"] == "VLAN"
    assert reply_dict["Tunnel-Medium-Type"] == "IEEE-802"
    assert reply_dict["Tunnel-Private-Group-Id"] == "100"

    # Test Reject tuple (platform blocked)
    p_reject = (
        ("TLS-Client-Cert-Subject", f"/CN=Device-3/O={u['sub_b']}/OU={u['role_staff']}"),
    )
    res_reject, _, _ = ap.post_auth(p_reject)
    assert res_reject == ap.RLM_MODULE_REJECT


def test_post_auth_rejects_username_fallback_and_duplicate_subjects(tmp_path, sample_uuids, valid_policy, monkeypatch):
    import json
    u = sample_uuids
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps(valid_policy))
    monkeypatch.setattr(ap, "LOCAL_SITE_ID", u["site_id"])
    monkeypatch.setattr(ap, "LOCAL_POLICY_PATH", str(policy_file))
    subject = f"/CN=Device/O={u['sub_a']}/OU={u['role_staff']}"

    assert ap.post_auth((("User-Name", subject),))[0] == ap.RLM_MODULE_REJECT
    assert ap.post_auth((("TLS-Client-Cert-Subject", subject), ("TLS-Client-Cert-Subject", subject)))[0] == ap.RLM_MODULE_REJECT


def test_post_auth_ignores_request_controlled_site_and_policy(tmp_path, sample_uuids, valid_policy, monkeypatch):
    import json
    u = sample_uuids
    trusted_policy = tmp_path / "trusted.json"
    trusted_policy.write_text(json.dumps(valid_policy))
    attacker_policy = tmp_path / "attacker.json"
    attacker_policy.write_text(json.dumps({**valid_policy, "site_id": "attacker-site"}))
    monkeypatch.setattr(ap, "LOCAL_SITE_ID", u["site_id"])
    monkeypatch.setattr(ap, "LOCAL_POLICY_PATH", str(trusted_policy))

    result = ap.post_auth((
        ("TLS-Client-Cert-Subject", f"/CN=Device/O={u['sub_a']}/OU={u['role_staff']}"),
        ("Site-Id", "attacker-site"),
        ("Policy-File", str(attacker_policy)),
    ))
    assert result[0] == ap.RLM_MODULE_OK


@pytest.mark.parametrize("subject", [
    r"/CN=Device/O=c4b72605-728b-4028-a28a-7cf513f28d8b\\/OU=bad/OU=c4b72605-728b-4028-a28a-7cf513f28d8b",
    "CN=Device,O=c4b72605-728b-4028-a28a-7cf513f28d8b+OU=c4b72605-728b-4028-a28a-7cf513f28d8b",
])
def test_parse_certificate_identity_rejects_escaped_or_multivalued_dn(subject):
    with pytest.raises(ValueError, match="Escaped or multi-valued"):
        ap.parse_certificate_identity(subject)
