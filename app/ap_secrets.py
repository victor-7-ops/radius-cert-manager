"""AP shared-secret encryption at rest (handoff task M, 24 Nov 2026).

Secrets must be reversible (clients.conf needs the plaintext), unlike
password hashing -- so Fernet symmetric encryption, keyed by a file
generated once and kept out of the repo, same pattern as
site_policy.get_or_create_policy_signing_key.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

_KEY_FILENAME = "ap_secrets.key"


def get_or_create_key(pki_path: Path) -> bytes:
    key_file = pki_path / "private" / _KEY_FILENAME
    if key_file.exists():
        return key_file.read_bytes()

    key_file.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except Exception:
        pass
    return key


def encrypt_secret(plaintext: str, pki_path: Path) -> str:
    return Fernet(get_or_create_key(pki_path)).encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str, pki_path: Path) -> str:
    return Fernet(get_or_create_key(pki_path)).decrypt(ciphertext.encode()).decode()
