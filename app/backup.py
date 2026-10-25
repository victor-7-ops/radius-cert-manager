"""Backup/restore core (HANDOFF-FLEET.md §8.4): DB, pki/issued/, and the
intermediate key into one timestamped, passphrase-encrypted archive.
"An untested backup is a belief, not a backup" — this module is the
shared logic behind scripts/backup.py and scripts/restore_check.py so
the two can never silently drift on the archive format.

Never writes plaintext key material to the archive: the tar is built in
memory and only ever touches disk already encrypted.
"""

from __future__ import annotations

import base64
import io
import os
import shutil
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"CMBK1"  # archive format tag, so a stray file isn't mistaken for a backup
SALT_LEN = 16
PBKDF2_ITERATIONS = 390_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


@dataclass
class BackupContents:
    db_path: Path
    pki_path: Path


def _add_file(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    if path.exists():
        tar.add(path, arcname=arcname)


def _snapshot_db(db_path: Path) -> tuple[Path, Path | None]:
    """Takes a consistent point-in-time SQLite snapshot using the online backup
    API so active WAL transactions and dirty pages are cleanly consolidated."""
    if not db_path.exists():
        return db_path, None
    temp_dir = Path(tempfile.mkdtemp(prefix="cm_bk_snap_"))
    temp_file = temp_dir / "certmanager.db"
    try:
        src = sqlite3.connect(str(db_path))
        dest = sqlite3.connect(str(temp_file))
        with dest:
            src.backup(dest)
        dest.close()
        src.close()
        return temp_file, temp_dir
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return db_path, None


def build_archive(contents: BackupContents, passphrase: str) -> bytes:
    """Returns the encrypted archive bytes — nothing plaintext ever
    touches the caller's disk unless the caller chooses to write this
    return value there directly."""
    tar_buffer = io.BytesIO()
    db_to_add, cleanup_dir = _snapshot_db(contents.db_path)
    try:
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            _add_file(tar, db_to_add, "certmanager.db")
            _add_file(tar, contents.pki_path / "intermediate.crt", "pki/intermediate.crt")
            _add_file(tar, contents.pki_path / "ca-chain.pem", "pki/ca-chain.pem")
            _add_file(
                tar, contents.pki_path / "private" / "intermediate.key",
                "pki/private/intermediate.key",
            )
            issued_dir = contents.pki_path / "issued"
            if issued_dir.exists():
                tar.add(issued_dir, arcname="pki/issued")
    finally:
        if cleanup_dir and cleanup_dir.exists():
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    salt = os.urandom(SALT_LEN)
    key = _derive_key(passphrase, salt)
    encrypted = Fernet(key).encrypt(tar_buffer.getvalue())
    return MAGIC + salt + encrypted


class InvalidPassphraseError(Exception):
    pass


class NotABackupArchiveError(Exception):
    pass


def decrypt_archive(data: bytes, passphrase: str) -> bytes:
    """Returns the decrypted tar.gz bytes. Raises NotABackupArchiveError
    if the magic tag doesn't match (wrong file entirely), or
    InvalidPassphraseError if the tag matches but decryption fails
    (wrong passphrase, or corrupted archive — Fernet can't tell those
    apart, and callers shouldn't need to)."""
    if not data.startswith(MAGIC):
        raise NotABackupArchiveError("not a certmanager backup archive")
    salt = data[len(MAGIC):len(MAGIC) + SALT_LEN]
    encrypted = data[len(MAGIC) + SALT_LEN:]
    key = _derive_key(passphrase, salt)
    try:
        return Fernet(key).decrypt(encrypted)
    except InvalidToken:
        raise InvalidPassphraseError("wrong passphrase or corrupted archive")


def extract_archive(tar_bytes: bytes, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        # filter="data" (Python 3.12+) refuses path traversal / absolute
        # members — this archive is our own output, but restore code is
        # exactly the wrong place to trust that blindly.
        tar.extractall(dest_dir, filter="data")
