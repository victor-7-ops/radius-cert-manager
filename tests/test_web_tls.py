"""Optional TLS for uvicorn (HANDOFF-NANO-DEPLOY.md §6) — unset by
default (plain HTTP, unchanged behavior), both-or-neither if set."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from serve import uvicorn_kwargs  # noqa: E402


def test_no_ssl_settings_means_plain_http(app_settings):
    kwargs = uvicorn_kwargs(app_settings)
    assert "ssl_keyfile" not in kwargs
    assert "ssl_certfile" not in kwargs
    assert kwargs["host"] == app_settings.bind_host
    assert kwargs["port"] == app_settings.bind_port


def test_both_ssl_settings_passed_through(app_settings, tmp_path):
    key = tmp_path / "web.key"
    cert = tmp_path / "web.crt"
    app_settings.web_ssl_keyfile = key
    app_settings.web_ssl_certfile = cert
    kwargs = uvicorn_kwargs(app_settings)
    assert kwargs["ssl_keyfile"] == str(key)
    assert kwargs["ssl_certfile"] == str(cert)


def test_config_rejects_only_one_ssl_setting_set(tmp_path, monkeypatch):
    pki_dir = tmp_path / "pki"
    (pki_dir / "private").mkdir(parents=True)
    (pki_dir / "issued").mkdir(parents=True)
    (tmp_path / "ssh_key").write_text("fake")
    env = {
        "SECRET_KEY": "x" * 40,
        "PKI_PATH": str(pki_dir),
        "DB_PATH": str(tmp_path / "certmanager.db"),
        "BIND_HOST": "127.0.0.1",
        "BIND_PORT": "8443",
        "RADIUS_HOST": "127.0.0.1",
        "RADIUS_SSH_KEY": str(tmp_path / "ssh_key"),
        "RADIUS_SSH_USER": "crlpush",
        "WEB_SSL_KEYFILE": str(tmp_path / "web.key"),
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    from app.config import load_settings

    with pytest.raises(Exception, match="WEB_SSL_KEYFILE and WEB_SSL_CERTFILE"):
        load_settings()
