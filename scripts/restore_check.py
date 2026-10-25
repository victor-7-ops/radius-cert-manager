"""Restore drill (HANDOFF-FLEET.md §8.4): decrypt a backup archive into a
scratch directory, open the DB, verify the cert count, and verify the
restored chain with openssl. Exits non-zero on any failure so a timer
can run this unattended and page on failure — "an untested backup is a
belief, not a backup."

Usage:
    python -m scripts.restore_check /var/backups/certmanager/certmanager-backup-<ts>.cmbk
    python -m scripts.restore_check --latest-in /var/backups/certmanager

--latest-in picks the most recently modified *.cmbk in that directory —
what a systemd timer uses, so it doesn't need to know today's backup's
exact filename.

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

    key_path = scratch_dir / "pki" / "private" / "intermediate.key"
    if key_path.exists():
        try:
            from cryptography.hazmat.primitives import serialization
            from app import pki

            cert = pki.load_cert_pem(intermediate_crt)
            key = pki.load_key_pem(key_path)
            pub_cert = cert.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key = key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if pub_cert != pub_key:
                return _fail("restored intermediate key does not match restored intermediate cert")
        except Exception as e:
            return _fail(f"could not read restored cert/key: {e}")

    ca_chain = scratch_dir / "pki" / "ca-chain.pem"
    if ca_chain.exists():
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import ec
            from app import pki

            inter_cert = pki.load_cert_pem(intermediate_crt)
            chain_certs = x509.load_pem_x509_certificates(ca_chain.read_bytes())
            issuer_cert = next((c for c in chain_certs if c.subject == inter_cert.issuer), None)
            if issuer_cert is None:
                return _fail("no certificate in ca-chain.pem matches intermediate.crt issuer")
            if isinstance(issuer_cert.public_key(), ec.EllipticCurvePublicKey):
                issuer_cert.public_key().verify(
                    inter_cert.signature,
                    inter_cert.tbs_certificate_bytes,
                    ec.ECDSA(inter_cert.signature_hash_algorithm),
                )
            else:
                from cryptography.hazmat.primitives.asymmetric import padding
                issuer_cert.public_key().verify(
                    inter_cert.signature,
                    inter_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    inter_cert.signature_hash_algorithm,
                )
        except Exception as e:
            return _fail(f"verify failed against restored chain: {e}")
    elif not key_path.exists():
        return _fail("no ca-chain.pem and no intermediate.key to verify against")

    print(f"Restore check OK: {cert_count} certificates, chain/key verified.")
    return 0


def find_latest_archive(directory: Path) -> Path | None:
    candidates = sorted(directory.glob("*.cmbk"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, nargs="?")
    parser.add_argument(
        "--latest-in", type=Path, metavar="DIR",
        help="check the most recently modified *.cmbk in DIR, instead of naming one explicitly",
    )
    args = parser.parse_args()

    if bool(args.archive) == bool(args.latest_in):
        return _fail("pass exactly one of: an archive path, or --latest-in DIR")

    if args.latest_in is not None:
        archive_path = find_latest_archive(args.latest_in)
        if archive_path is None:
            return _fail(f"no *.cmbk archives found in {args.latest_in}")
    else:
        archive_path = args.archive
        if not archive_path.exists():
            return _fail(f"no such archive: {archive_path}")

    passphrase = os.environ.get("BACKUP_PASSPHRASE") or getpass.getpass(
        "Backup encryption passphrase: "
    )

    with tempfile.TemporaryDirectory(prefix="cm-restore-check-") as scratch:
        return check_restore(archive_path, passphrase, Path(scratch))


if __name__ == "__main__":
    raise SystemExit(main())
