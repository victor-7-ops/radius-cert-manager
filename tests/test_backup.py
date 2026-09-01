"""Backup/restore (HANDOFF-FLEET.md §8.4). Covers the encrypt/decrypt
round trip in app/backup.py and the restore-drill logic in
scripts/restore_check.py — never against a real archive on a real host,
same isolation rule as the rest of this suite."""

import sqlite3
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from app import backup as backup_module
from app import db
import restore_check  # noqa: E402


def _seeded_pki_dir(tmp_path, throwaway_pki):
    from app import pki

    pki_dir = tmp_path / "pki"
    (pki_dir / "private").mkdir(parents=True)
    issued_dir = pki_dir / "issued"
    issued_dir.mkdir()
    (pki_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (pki_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )
    (issued_dir / "device-1.123.crt").write_bytes(b"fake cert bytes")
    return pki_dir


def _seeded_db(tmp_path):
    db_path = tmp_path / "certmanager.db"
    engine = db.make_engine(str(db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(db.Certificate(
        id=str(uuid.uuid4()), cn="device-1", serial="123", issued_at=now,
        expires_at=now + datetime.timedelta(days=365), status=db.CertStatus.active,
        issued_by="alice", request_id=str(uuid.uuid4()),
    ))
    session.commit()
    return db_path


def test_build_archive_never_contains_plaintext_key(tmp_path, throwaway_pki):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)

    archive = backup_module.build_archive(
        backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="correct horse battery staple",
    )

    # The raw key PEM bytes must not appear anywhere in the archive —
    # everything past the magic tag + salt is Fernet ciphertext.
    from app import pki
    key_pem = pki.private_key_to_pem(throwaway_pki["inter_key"])
    assert key_pem not in archive
    assert archive.startswith(backup_module.MAGIC)


def test_decrypt_with_wrong_passphrase_raises(tmp_path, throwaway_pki):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)
    archive = backup_module.build_archive(
        backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="right-passphrase",
    )

    try:
        backup_module.decrypt_archive(archive, "wrong-passphrase")
        assert False, "expected InvalidPassphraseError"
    except backup_module.InvalidPassphraseError:
        pass


def test_decrypt_non_backup_file_raises(tmp_path):
    try:
        backup_module.decrypt_archive(b"not a backup at all", "whatever")
        assert False, "expected NotABackupArchiveError"
    except backup_module.NotABackupArchiveError:
        pass


def test_round_trip_extracts_db_and_pki_contents(tmp_path, throwaway_pki):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)
    archive = backup_module.build_archive(
        backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="s3cret-phrase",
    )

    tar_bytes = backup_module.decrypt_archive(archive, "s3cret-phrase")
    dest = tmp_path / "restored"
    backup_module.extract_archive(tar_bytes, dest)

    assert (dest / "certmanager.db").exists()
    assert (dest / "pki" / "intermediate.crt").exists()
    assert (dest / "pki" / "private" / "intermediate.key").exists()
    assert (dest / "pki" / "issued" / "device-1.123.crt").exists()

    conn = sqlite3.connect(str(dest / "certmanager.db"))
    count = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    conn.close()
    assert count == 1


def test_restore_check_passes_end_to_end(tmp_path, throwaway_pki):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)
    archive_path = tmp_path / "backup.cmbk"
    archive_path.write_bytes(
        backup_module.build_archive(
            backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="drill-phrase",
        )
    )

    rc = restore_check.check_restore(archive_path, "drill-phrase", tmp_path / "scratch")
    assert rc == 0


def test_restore_check_fails_on_wrong_passphrase(tmp_path, throwaway_pki):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)
    archive_path = tmp_path / "backup.cmbk"
    archive_path.write_bytes(
        backup_module.build_archive(
            backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="drill-phrase",
        )
    )

    rc = restore_check.check_restore(archive_path, "wrong-phrase", tmp_path / "scratch2")
    assert rc != 0


def test_restore_check_fails_on_empty_cert_count(tmp_path, throwaway_pki):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    empty_db_path = tmp_path / "empty.db"
    engine = db.make_engine(str(empty_db_path))
    db.init_db(engine)  # no certs added

    archive_path = tmp_path / "backup.cmbk"
    archive_path.write_bytes(
        backup_module.build_archive(
            backup_module.BackupContents(db_path=empty_db_path, pki_path=pki_dir), passphrase="p",
        )
    )

    rc = restore_check.check_restore(archive_path, "p", tmp_path / "scratch3")
    assert rc != 0


def test_restore_check_fails_when_key_does_not_match_cert(tmp_path, throwaway_pki):
    """A corrupted/mismatched restore must be caught, not silently
    reported as fine (HANDOFF-FLEET.md §8.4 acceptance)."""
    from app import pki as pkimod

    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)

    # Swap in an unrelated key after building the "clean" pki dir, so the
    # archive captures a cert/key pair that don't match.
    other_key = pkimod.generate_private_key()
    (pki_dir / "private" / "intermediate.key").write_bytes(pkimod.private_key_to_pem(other_key))

    archive_path = tmp_path / "backup.cmbk"
    archive_path.write_bytes(
        backup_module.build_archive(
            backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="p",
        )
    )

    rc = restore_check.check_restore(archive_path, "p", tmp_path / "scratch4")
    assert rc != 0
