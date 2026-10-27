"""FreeRADIUS EAP-TLS local authorization adapter for tenant network roles and VLAN policy.

Implements B06 specification:
- Pure local policy evaluation; zero live hub calls during 802.1X authentication
- Extracts signed O=<subsidiary UUID> and OU=<network-role UUID> from TLS client cert
- Enforces strict single-cardinality and UUID format for O and OU
- Rejects expired policy leases and mismatched site IDs (fail closed)
- Evaluates authoritative decision tree:
    * Platform block -> REJECT
    * Role ON (role_active AND tenant_enabled) -> Primary VLAN
    * Role OFF (either tenant switch OFF) -> Explicit Fallback VLAN (or REJECT if unconfigured)
    * Nonexistent binding or tenant -> REJECT
- Standard FreeRADIUS rlm_python3 module interface + standalone testable API
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("authorize_policy")

# These values are trusted local module configuration.  Request pairs must
# never be allowed to select a tenant/site or a policy file.
LOCAL_SITE_ID = os.environ.get("CERTMANAGER_SITE_ID", "").strip()
LOCAL_POLICY_PATH = os.environ.get("CERTMANAGER_POLICY_FILE", "").strip()

# FreeRADIUS rlm_python3 constants (defined locally for testability without freeradius C module)
RLM_MODULE_REJECT = 0
RLM_MODULE_FAIL = 1
RLM_MODULE_OK = 2
RLM_MODULE_HANDLED = 3
RLM_MODULE_INVALID = 4
RLM_MODULE_USERREQ = 5
RLM_MODULE_NOTFOUND = 6
RLM_MODULE_NOOP = 7
RLM_MODULE_UPDATED = 8


@dataclass(frozen=True)
class RadiusDecision:
    outcome: Literal["accept", "reject"]
    vlan_id: int | None
    vlan_type: Literal["primary", "fallback"] | None
    reason: str
    subsidiary_id: str | None = None
    network_role_id: str | None = None


def parse_certificate_identity(subject_str: str) -> tuple[str, str]:
    """Parses X.509 Subject string and returns (subsidiary_uuid, network_role_uuid).
    
    Supports both OpenSSL oneline format (/CN=.../O=.../OU=...) and RFC 2253 (CN=...,O=...,OU=...).
    Enforces strict single cardinality for O and OU, and valid UUID syntax.
    """
    if not subject_str or not subject_str.strip():
        raise ValueError("Empty certificate subject")

    # Accept only an intentionally small, unescaped subset of OpenSSL oneline
    # and RFC 2253 display forms.  Escapes and multi-valued RDNs are rejected
    # because treating a display DN as a general-purpose parser is unsafe.
    if any(char in subject_str for char in ("\\", "+", ";", "\x00", "\r", "\n")):
        raise ValueError("Escaped or multi-valued certificate subjects are not supported")

    if subject_str.startswith("/"):
        raw_components = subject_str[1:].split("/")
    elif "/" in subject_str:
        raise ValueError("Malformed OpenSSL certificate subject")
    else:
        raw_components = subject_str.split(",")

    components: list[tuple[str, str]] = []
    for raw_component in raw_components:
        component = raw_component.strip()
        if not component or "=" not in component:
            raise ValueError("Malformed certificate subject component")
        name, value = component.split("=", 1)
        name = name.strip().upper()
        value = value.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9.-]*", name) or not value:
            raise ValueError("Malformed certificate subject component")
        components.append((name, value))

    o_matches = [value for name, value in components if name == "O"]
    ou_matches = [value for name, value in components if name == "OU"]

    if len(o_matches) != 1:
        raise ValueError(f"Expected exactly 1 O (subsidiary) component in subject, found {len(o_matches)}")
    if len(ou_matches) != 1:
        raise ValueError(f"Expected exactly 1 OU (network-role) component in subject, found {len(ou_matches)}")

    sub_id = o_matches[0].strip()
    role_id = ou_matches[0].strip()

    try:
        uuid.UUID(sub_id)
    except ValueError:
        raise ValueError(f"O component '{sub_id}' is not a valid UUID")

    try:
        uuid.UUID(role_id)
    except ValueError:
        raise ValueError(f"OU component '{role_id}' is not a valid UUID")

    return sub_id, role_id


def evaluate_authorization(
    subject_str: str,
    policy_data: dict[str, Any],
    expected_site_id: str,
    now: datetime.datetime | None = None,
) -> RadiusDecision:
    """Evaluates client identity against verified local site policy.
    
    Zero network access; pure local lookup.
    """
    try:
        sub_id, role_id = parse_certificate_identity(subject_str)
    except ValueError as e:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason=f"Certificate identity parse failure: {e}",
        )

    # 1. Policy schema and site validation
    schema_ver = policy_data.get("schema_version")
    if schema_ver != 2:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason=f"Unsupported policy schema version {schema_ver}",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    policy_site_id = policy_data.get("site_id")
    if policy_site_id != expected_site_id:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason=f"Policy site_id '{policy_site_id}' does not match local site '{expected_site_id}'",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    # 2. Expiration check (fail closed)
    expires_str = policy_data.get("expires_at")
    if not expires_str:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason="Missing expires_at in local policy",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )
    try:
        expires_at = datetime.datetime.fromisoformat(expires_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    except Exception as e:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason=f"Invalid policy expires_at timestamp: {e}",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    now_dt = now or datetime.datetime.now(datetime.timezone.utc)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=datetime.timezone.utc)

    if expires_at <= now_dt:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason=f"Local policy expired at {expires_at.isoformat()} (fail closed)",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    # 3. Lookup binding for (subsidiary_id, network_role_id)
    bindings = policy_data.get("bindings", [])
    matching_binding = None
    for b in bindings:
        if b.get("subsidiary_id") == sub_id and b.get("network_role_id") == role_id:
            matching_binding = b
            break

    if not matching_binding:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason=f"No binding for tenant {sub_id} and role {role_id} at this site",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    # 4. Check platform block: platform block ALWAYS rejects, never triggers fallback
    platform_enabled = matching_binding.get("platform_enabled", True)
    if not platform_enabled:
        return RadiusDecision(
            outcome="reject",
            vlan_id=None,
            vlan_type=None,
            reason="Platform superadmin has disabled access for this site binding",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    # 5. Check tenant switches (role_active AND tenant_enabled)
    role_active = matching_binding.get("role_active", True)
    tenant_enabled = matching_binding.get("tenant_enabled", True)
    primary_vlan = matching_binding.get("primary_vlan_id")
    fallback_vlan = matching_binding.get("fallback_vlan_id")

    if role_active and tenant_enabled:
        if not (1 <= primary_vlan <= 4094):
            return RadiusDecision(
                outcome="reject",
                vlan_id=None,
                vlan_type=None,
                reason=f"Invalid primary VLAN ID {primary_vlan}",
                subsidiary_id=sub_id,
                network_role_id=role_id,
            )
        return RadiusDecision(
            outcome="accept",
            vlan_id=primary_vlan,
            vlan_type="primary",
            reason="Authorized: normal network role is ON",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    # Role is OFF -> Explicit Fallback VLAN
    if fallback_vlan is not None and (1 <= fallback_vlan <= 4094) and fallback_vlan != primary_vlan:
        return RadiusDecision(
            outcome="accept",
            vlan_id=fallback_vlan,
            vlan_type="fallback",
            reason="Role switch is OFF: assigned explicitly configured fallback VLAN",
            subsidiary_id=sub_id,
            network_role_id=role_id,
        )

    return RadiusDecision(
        outcome="reject",
        vlan_id=None,
        vlan_type=None,
        reason="Role switch is OFF and no valid fallback VLAN is configured",
        subsidiary_id=sub_id,
        network_role_id=role_id,
    )


def load_policy_file(policy_path: str | Path) -> dict[str, Any]:
    """Loads and parses local policy.json."""
    path = Path(policy_path)
    if not path.is_file():
        raise FileNotFoundError(f"Policy file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# --- FreeRADIUS rlm_python3 module callbacks ---

def post_auth(p: tuple) -> tuple:
    """FreeRADIUS rlm_python3 post_auth hook.
    
    Called by FreeRADIUS after successful TLS handshake and CRL verification.
    """
    # Extract request dictionary from FreeRADIUS tuple pairs
    req = dict(p) if isinstance(p, (dict, list, tuple)) else {}

    subject_values = [value for key, value in (p if isinstance(p, (list, tuple)) else ())
                      if key == "TLS-Client-Cert-Subject"]
    if isinstance(p, dict):
        value = p.get("TLS-Client-Cert-Subject")
        subject_values = [value] if value is not None else []

    if len(subject_values) != 1 or not isinstance(subject_values[0], str):
        logger.warning("Access-Reject: expected exactly one trusted TLS client certificate subject")
        return (RLM_MODULE_REJECT, (), ())
    if not LOCAL_SITE_ID or not LOCAL_POLICY_PATH:
        logger.error("RADIUS policy module local site/policy configuration is incomplete")
        return (RLM_MODULE_REJECT, (), ())

    client_subject = subject_values[0]
    site_id = LOCAL_SITE_ID
    policy_path = LOCAL_POLICY_PATH

    try:
        policy_data = load_policy_file(policy_path)
        decision = evaluate_authorization(client_subject, policy_data, expected_site_id=site_id)
    except Exception as e:
        logger.error("RADIUS policy authorization error: %s", e)
        return (RLM_MODULE_REJECT, (), ())

    if decision.outcome == "accept" and decision.vlan_id is not None:
        reply = (
            ("Tunnel-Type", "VLAN"),
            ("Tunnel-Medium-Type", "IEEE-802"),
            ("Tunnel-Private-Group-Id", str(decision.vlan_id)),
        )
        logger.info(
            "Access-Accept: site=%s sub=%s role=%s vlan=%d (%s)",
            site_id, decision.subsidiary_id, decision.network_role_id, decision.vlan_id, decision.vlan_type
        )
        return (RLM_MODULE_OK, reply, ())
    else:
        logger.warning(
            "Access-Reject: site=%s sub=%s role=%s reason=%s",
            site_id, decision.subsidiary_id, decision.network_role_id, decision.reason
        )
        return (RLM_MODULE_REJECT, (), ())
