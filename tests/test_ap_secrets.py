from app import ap_secrets


def test_encrypt_decrypt_roundtrip(tmp_path):
    ciphertext = ap_secrets.encrypt_secret("hunter2", tmp_path)
    assert ciphertext != "hunter2"
    assert ap_secrets.decrypt_secret(ciphertext, tmp_path) == "hunter2"


def test_key_is_persisted_and_reused(tmp_path):
    ap_secrets.encrypt_secret("hunter2", tmp_path)
    key_file = tmp_path / "private" / "ap_secrets.key"
    assert key_file.exists()
    first_key = key_file.read_bytes()

    ap_secrets.encrypt_secret("other", tmp_path)
    assert key_file.read_bytes() == first_key
