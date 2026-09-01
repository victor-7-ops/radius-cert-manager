"""Restore drill (HANDOFF-FLEET.md §8.4): decrypt a backup archive into a
scratch directory, open the DB, verify the cert count, and verify the
restored chain with openssl. Exits non-zero on any failure so a timer
can run this unattended and page on failure — "an untested backup is a
belief, not a backup."

Usage:
    python -m scripts.restore_check /var/backups/certmanager/certmanager-backup-*.cmbk

Passphrase comes from $BACKUP_PASSPHRASE if set, otherwise prompted.
"""

from __future__ import annotations

import argparse
import getpass
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.backup import InvalidPassphraseError, NotABackupArchiveError, decrypt_archive, extract_archive


def _fail(message: str) -> int:
    print(f"RESTORE CHECK FAILED: {message}", file=sys.stderr)
    return 1


def check_restore(archive_path: Path, passphrase: str, scratch_dir: Path) -> int:
    try:
        tar_bytes = decrypt_archive(archive_path.read_bytes(), passphrase)
    except NotABackupArchiveError as e:
        return _fail(str(e))
    except InvalidPassphraseError as e:
        return _fail(str(e))

    extract_archive(tar_bytes, scratch_dir)

    db_path = scratch_dir / "certmanager.db"
    if not db_path.exists():
        return _fail("archive did not contain certmanager.db")

    conn = sqlite3.connect(str(db_path))
    try:
        cert_count = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    except sqlite3.OperationalError as e:
        conn.close()
        return _fail(f"restored DB is not openable / missing certificates table: {e}")
    conn.close()

    if cert_count == 0:
        return _fail("restored DB has zero certificates — refusing to call this a success")

    intermediate_crt = scratch_dir / "pki" / "intermediate.crt"
    if not intermediate_crt.exists():
        return _fail("archive did not contain pki/intermediate.crt")

    ca_chain = scratch_dir / "pki" / "ca-chain.pem"
    if ca_chain.exists():
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca_chain), str(intermediate_crt)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return _fail(f"openssl verify failed against restored chain: {result.stderr.strip()}")
    else:
        # No chain in this archive (e.g. root-CA-signing step wasn't part
        # of this backup) — fall back to proving the restored key
        # actually matches the restored cert, which is the failure mode
        # that matters most for "the backup is silently useless".
        key_path = scratch_dir / "pki" / "private" / "intermediate.key"
        if not key_path.exists():
            return _fail("no ca-chain.pem and no intermediate.key to verify against")
        cert_modulus = subprocess.run(
            ["openssl", "x509", "-in", str(intermediate_crt), "-noout", "-pubkey"],
            capture_output=True, text=True,
        )
        key_modulus = subprocess.run(
            ["openssl", "pkey", "-in", str(key_path), "-pubout"],
            capture_output=True, text=True,
        )
        if cert_modulus.returncode != 0 or key_modulus.returncode != 0:
            return _fail("openssl could not read restored cert/key")
        if cert_modulus.stdout != key_modulus.stdout:
            return _fail("restored intermediate key does not match restored intermediate cert")

    print(f"Restore check OK: {cert_count} certificates, chain/key verified.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()

    if not args.archive.exists():
        return _fail(f"no such archive: {args.archive}")

    passphrase = os.environ.get("BACKUP_PASSPHRASE") or getpass.getpass(
        "Backup encryption passphrase: "
    )

    with tempfile.TemporaryDirectory(prefix="cm-restore-check-") as scratch:
        return check_restore(args.archive, passphrase, Path(scratch))


if __name__ == "__main__":
    raise SystemExit(main())
