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


def test_find_latest_archive_picks_most_recently_modified(tmp_path):
    import os
    import time

    (tmp_path / "certmanager-backup-old.cmbk").write_bytes(b"old")
    time.sleep(0.01)
    newest = tmp_path / "certmanager-backup-new.cmbk"
    newest.write_bytes(b"new")
    # Explicit mtime bump — some filesystems have coarse mtime
    # resolution, and this test shouldn't be flaky because of that.
    os.utime(newest, None)

    assert restore_check.find_latest_archive(tmp_path) == newest


def test_find_latest_archive_returns_none_when_empty(tmp_path):
    assert restore_check.find_latest_archive(tmp_path) is None


def test_main_rejects_both_archive_and_latest_in(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", ["restore_check.py", str(tmp_path / "x.cmbk"), "--latest-in", str(tmp_path)])
    rc = restore_check.main()
    assert rc != 0
    assert "exactly one" in capsys.readouterr().err


def test_main_rejects_neither_archive_nor_latest_in(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["restore_check.py"])
    rc = restore_check.main()
    assert rc != 0
    assert "exactly one" in capsys.readouterr().err


def test_main_latest_in_finds_and_checks_archive(monkeypatch, tmp_path, throwaway_pki, capsys):
    pki_dir = _seeded_pki_dir(tmp_path, throwaway_pki)
    db_path = _seeded_db(tmp_path)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "certmanager-backup-20260101T000000Z.cmbk"
    archive_path.write_bytes(
        backup_module.build_archive(
            backup_module.BackupContents(db_path=db_path, pki_path=pki_dir), passphrase="p",
        )
    )

    monkeypatch.setenv("BACKUP_PASSPHRASE", "p")
    monkeypatch.setattr(sys, "argv", ["restore_check.py", "--latest-in", str(backup_dir)])
    rc = restore_check.main()
    assert rc == 0
    assert "Restore check OK" in capsys.readouterr().out
