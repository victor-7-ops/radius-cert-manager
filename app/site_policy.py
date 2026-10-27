"""Signed site network policy synchronization, Ed25519 compilation, and envelope verification.

Implements B05 specifications:
- Ed25519 dedicated policy signing keys and pinned public key verification
- Monotonic revisioning and tamper-evident base64 payload/signature envelopes
- Deterministic canonical JSON encoding with duplicate-key rejection
- 24-hour lease duration with expiry checks and replay protection
- Atomic compiled bindings for FreeRADIUS authorization adapter
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db

logger = logging.getLogger(__name__)

POLICY_SCHEMA_VERSION = 2
DEFAULT_LEASE_HOURS = 24


class PolicySyncError(Exception):
    """Base exception for policy synchronization errors."""
    pass


class PolicyEnvelopeError(PolicySyncError):
    """Malformed envelope, base64 failure, or missing required envelope fields."""
    pass


class PolicySignatureError(PolicySyncError):
    """Ed25519 signature verification failed or wrong public key used."""
    pass


class PolicyExpiredError(PolicySyncError):
    """Policy lease has expired."""
    pass


class PolicyReplayError(PolicySyncError):
    """Policy revision is lower than the currently installed monotonic revision."""
    pass


class PolicySchemaError(PolicySyncError):
    """Payload schema validation error, wrong site ID, or invalid VLAN values."""
    pass


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _as_utc(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def generate_policy_signing_key() -> tuple[ed25519.Ed25519PrivateKey, str]:
    """Generates an Ed25519 private key for policy signing and returns (private_key, key_id)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
    return priv, key_id


def export_private_key_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key_pem(pem_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise PolicyEnvelopeError("Key is not an Ed25519 private key")
    return key


def export_public_key_pem(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key_pem(pem_bytes: bytes) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise PolicyEnvelopeError("Key is not an Ed25519 public key")
    return key


def get_public_key_id(key: ed25519.Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def get_or_create_policy_signing_key(pki_path: Path) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Retrieves or generates the persistent policy signing Ed25519 key pair in the PKI directory."""
    key_file = pki_path / "private" / "policy_signing.key"
    pub_file = pki_path / "policy_signing.pub"
    if key_file.exists():
        priv = load_private_key_pem(key_file.read_bytes())
        pub = priv.public_key()
        if not pub_file.exists():
            pub_file.write_bytes(export_public_key_pem(pub))
        return priv, pub

    key_file.parent.mkdir(parents=True, exist_ok=True)
    priv, _ = generate_policy_signing_key()
    pub = priv.public_key()
    key_file.write_bytes(export_private_key_pem(priv))
    try:
        key_file.chmod(0o600)
    except Exception:
        pass
    pub_file.write_bytes(export_public_key_pem(pub))
    return priv, pub


def _reject_duplicate_keys_decoder():
    def _pairs_hook(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise PolicySchemaError(f"Duplicate key in JSON payload: {k}")
            obj[k] = v
        return obj
    return json.JSONDecoder(object_pairs_hook=_pairs_hook)


def canonical_json_bytes(data: Any) -> bytes:
    """Serializes data to canonical, deterministic UTF-8 JSON bytes (sorted keys, no extra whitespace)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def parse_canonical_json(raw_bytes: bytes) -> dict:
    """Parses UTF-8 JSON bytes rejecting duplicate keys."""
    try:
        text = raw_bytes.decode("utf-8")
        decoder = _reject_duplicate_keys_decoder()
        obj = decoder.decode(text)
        if not isinstance(obj, dict):
            raise PolicySchemaError("Policy JSON root must be an object")
        return obj
    except json.JSONDecodeError as e:
        raise PolicySchemaError(f"Malformed JSON: {e}") from e
    except UnicodeDecodeError as e:
        raise PolicySchemaError(f"JSON must be UTF-8 encoded: {e}") from e


def compile_site_policy(
    site: db.Site,
    session: Session,
    revision: int,
    lease_hours: int = DEFAULT_LEASE_HOURS,
    now: datetime.datetime | None = None,
) -> dict:
    """Compiles the authoritative, deterministic site policy payload for FreeRADIUS distribution.
    
    Contains active bindings, authorized subsidiaries, and role state switches.
    """
    now_dt = now or _now_utc()
    expires_dt = now_dt + datetime.timedelta(hours=lease_hours)

    # 1. Allowed subsidiaries for this site
    site_subs = session.scalars(
        select(db.SiteSubsidiary).where(
            db.SiteSubsidiary.site_id == site.id,
            db.SiteSubsidiary.is_active.is_(True),
        )
    ).all()
    allowed_sub_ids = {ss.subsidiary_id for ss in site_subs}

    # 2. Query all bindings for this site
    bindings_query = select(db.SiteRoleBinding).where(
        db.SiteRoleBinding.site_id == site.id
    )
    all_bindings = session.scalars(bindings_query).all()

    compiled_bindings = []
    for b in sorted(all_bindings, key=lambda x: (x.subsidiary_id, x.network_role_id)):
        # Site membership is an explicit allowlist.  An empty list withdraws
        # all bindings; it must never broaden access to every subsidiary.
        if b.subsidiary_id not in allowed_sub_ids:
            continue

        sub = session.get(db.Subsidiary, b.subsidiary_id)
        if not sub or not sub.is_active:
            continue

        role = session.get(db.NetworkRole, b.network_role_id)
        if not role or role.subsidiary_id != b.subsidiary_id:
            continue

        compiled_bindings.append({
            "subsidiary_id": b.subsidiary_id,
            "network_role_id": b.network_role_id,
            "primary_vlan_id": b.vlan_id,
            "fallback_vlan_id": b.fallback_vlan_id,
            "platform_enabled": b.platform_enabled,
            "tenant_enabled": b.tenant_enabled,
            "role_active": role.is_active,
            "config_revision": b.config_revision,
        })

    payload = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "site_id": site.id,
        "revision": revision,
        "issued_at": now_dt.isoformat(),
        "expires_at": expires_dt.isoformat(),
        "bindings": compiled_bindings,
    }
    return payload


def sign_policy_payload(
    payload: dict,
    private_key: ed25519.Ed25519PrivateKey,
    key_id: str | None = None,
) -> dict:
    """Signs canonical payload bytes with Ed25519 and returns the transport envelope."""
    payload_bytes = canonical_json_bytes(payload)
    sig = private_key.sign(payload_bytes)

    if not key_id:
        key_id = get_public_key_id(private_key.public_key())

    envelope = {
        "payload_base64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_base64": base64.b64encode(sig).decode("ascii"),
        "signing_key_id": key_id,
    }
    return envelope


def verify_policy_envelope(
    envelope: dict,
    public_key: ed25519.Ed25519PublicKey,
    expected_site_id: str,
    min_revision: int = 1,
    now: datetime.datetime | None = None,
) -> dict:
    """Verifies Ed25519 envelope signature and validates constraints against replay, expiry, and corruption.
    
    Returns the decoded and validated payload dict.
    """
    if not isinstance(envelope, dict):
        raise PolicyEnvelopeError("Envelope must be a JSON dictionary")

    payload_b64 = envelope.get("payload_base64")
    sig_b64 = envelope.get("signature_base64")
    key_id = envelope.get("signing_key_id")

    if not payload_b64 or not sig_b64 or not key_id:
        raise PolicyEnvelopeError("Envelope missing required fields: payload_base64, signature_base64, signing_key_id")

    expected_key_id = get_public_key_id(public_key)
    if key_id != expected_key_id:
        raise PolicySignatureError(f"Envelope signed by key ID {key_id}, expected pinned key ID {expected_key_id}")

    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception as e:
        raise PolicyEnvelopeError(f"Base64 decode failed: {e}") from e

    try:
        public_key.verify(sig_bytes, payload_bytes)
    except InvalidSignature as e:
        raise PolicySignatureError("Ed25519 signature is invalid for payload") from e

    payload = parse_canonical_json(payload_bytes)

    # 1. Schema check
    schema_ver = payload.get("schema_version")
    if schema_ver != POLICY_SCHEMA_VERSION:
        raise PolicySchemaError(f"Unsupported policy schema version {schema_ver}, expected {POLICY_SCHEMA_VERSION}")

    # 2. Site ID check
    site_id = payload.get("site_id")
    if site_id != expected_site_id:
        raise PolicySchemaError(f"Policy site_id '{site_id}' does not match expected site '{expected_site_id}'")

    # 3. Monotonic revision check
    revision = payload.get("revision")
    if not isinstance(revision, int) or revision < min_revision:
        raise PolicyReplayError(f"Policy revision {revision} is lower than minimum expected revision {min_revision}")

    # 4. Expiration check
    expires_str = payload.get("expires_at")
    if not expires_str:
        raise PolicySchemaError("Missing expires_at timestamp")
    try:
        expires_at = datetime.datetime.fromisoformat(expires_str)
    except Exception as e:
        raise PolicySchemaError(f"Invalid expires_at format: {e}") from e

    now_dt = now or _now_utc()
    if _as_utc(expires_at) <= _as_utc(now_dt):
        raise PolicyExpiredError(f"Policy lease expired at {expires_at.isoformat()} (current time {now_dt.isoformat()})")

    # 5. Bindings validation
    bindings = payload.get("bindings")
    if not isinstance(bindings, list):
        raise PolicySchemaError("Policy bindings must be a list")

    seen_keys = set()
    for b in bindings:
        if not isinstance(b, dict):
            raise PolicySchemaError("Binding must be a dictionary")
        sub_id = b.get("subsidiary_id")
        role_id = b.get("network_role_id")
        pvlan = b.get("primary_vlan_id")
        fvlan = b.get("fallback_vlan_id")

        if not sub_id or not role_id:
            raise PolicySchemaError("Binding missing subsidiary_id or network_role_id")

        key = (sub_id, role_id)
        if key in seen_keys:
            raise PolicySchemaError(f"Duplicate binding for subsidiary '{sub_id}' and role '{role_id}'")
        seen_keys.add(key)

        if not isinstance(pvlan, int) or not (1 <= pvlan <= 4094):
            raise PolicySchemaError(f"Invalid primary VLAN ID: {pvlan}")

        if fvlan is not None:
            if not isinstance(fvlan, int) or not (1 <= fvlan <= 4094):
                raise PolicySchemaError(f"Invalid fallback VLAN ID: {fvlan}")
            if fvlan == pvlan:
                raise PolicySchemaError("Fallback VLAN cannot equal primary VLAN")

    return payload


CODE_BUNDLE_SCHEMA_VERSION = 1


def sign_code_bundle(content: bytes, version: str, private_key: ed25519.Ed25519PrivateKey) -> dict:
    """Signs a code bundle (e.g. the FreeRADIUS adapter source) with the same
    Ed25519 key used for policy signing, so sites need only one pinned
    public key. Returns the transport envelope."""
    payload = {
        "schema_version": CODE_BUNDLE_SCHEMA_VERSION,
        "type": "radius_adapter",
        "version": version,
        "sha256": hashlib.sha256(content).hexdigest(),
        "content_base64": base64.b64encode(content).decode("ascii"),
    }
    return sign_policy_payload(payload, private_key)


def verify_code_bundle_envelope(envelope: dict, public_key: ed25519.Ed25519PublicKey) -> dict:
    """Verifies Ed25519 signature on a code-bundle envelope and returns the
    payload dict with decoded, hash-checked content under 'content_bytes'."""
    if not isinstance(envelope, dict):
        raise PolicyEnvelopeError("Envelope must be a JSON dictionary")

    payload_b64 = envelope.get("payload_base64")
    sig_b64 = envelope.get("signature_base64")
    key_id = envelope.get("signing_key_id")
    if not payload_b64 or not sig_b64 or not key_id:
        raise PolicyEnvelopeError("Envelope missing required fields: payload_base64, signature_base64, signing_key_id")

    expected_key_id = get_public_key_id(public_key)
    if key_id != expected_key_id:
        raise PolicySignatureError(f"Envelope signed by key ID {key_id}, expected pinned key ID {expected_key_id}")

    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except Exception as e:
        raise PolicyEnvelopeError(f"Base64 decode failed: {e}") from e

    try:
        public_key.verify(sig_bytes, payload_bytes)
    except InvalidSignature as e:
        raise PolicySignatureError("Ed25519 signature is invalid for payload") from e

    payload = parse_canonical_json(payload_bytes)

    if payload.get("schema_version") != CODE_BUNDLE_SCHEMA_VERSION:
        raise PolicySchemaError(f"Unsupported code bundle schema version {payload.get('schema_version')}")
    if payload.get("type") != "radius_adapter":
        raise PolicySchemaError(f"Unexpected bundle type {payload.get('type')!r}")

    try:
        content = base64.b64decode(payload["content_base64"], validate=True)
    except Exception as e:
        raise PolicyEnvelopeError(f"content_base64 decode failed: {e}") from e

    if hashlib.sha256(content).hexdigest() != payload.get("sha256"):
        raise PolicyEnvelopeError("content does not match declared sha256")

    payload["content_bytes"] = content
    return payload


def publish_site_policy(
    site_id: str,
    actor_username: str,
    session: Session,
    private_key: ed25519.Ed25519PrivateKey,
    lease_hours: int = DEFAULT_LEASE_HOURS,
) -> db.SitePolicyRevision:
    """Compiles, signs, and durably records a new immutable SitePolicyRevision in the database."""
    site = session.get(db.Site, site_id)
    if not site:
        raise PolicySchemaError(f"Site '{site_id}' not found")

    # Monotonic revision counter
    latest_rev = session.scalar(
        select(db.SitePolicyRevision.revision)
        .where(db.SitePolicyRevision.site_id == site_id)
        .order_by(db.SitePolicyRevision.revision.desc())
        .limit(1)
    ) or 0
    next_rev = latest_rev + 1

    payload = compile_site_policy(site, session, revision=next_rev, lease_hours=lease_hours)
    envelope = sign_policy_payload(payload, private_key)
    raw_envelope = canonical_json_bytes(envelope)
    payload_hash = hashlib.sha256(raw_envelope).hexdigest()

    now_dt = _now_utc()
    expires_dt = now_dt + datetime.timedelta(hours=lease_hours)

    rev_record = db.SitePolicyRevision(
        site_id=site_id,
        revision=next_rev,
        payload_json=raw_envelope.decode("utf-8"),
        payload_hash=payload_hash,
        signature=envelope["signature_base64"],
        signing_key_id=envelope["signing_key_id"],
        issued_at=now_dt,
        expires_at=expires_dt,
        actor=actor_username,
    )
    session.add(rev_record)
    session.flush()

    db.audit(
        session,
        actor=actor_username,
        action="site_policy.publish",
        target=f"{site.name}:rev{next_rev}",
        detail=f"Published site policy rev {next_rev} hash {payload_hash[:16]}",
        site_id=site.id,
    )
    return rev_record
