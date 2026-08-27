import os
os.environ.setdefault("SECRET_KEY", "demoDemoDemoDemoDemoDemoDemoDemo12345")
os.environ.setdefault("PKI_PATH", r"C:\cmdemo\pki")
os.environ.setdefault("DB_PATH", r"C:\cmdemo\certmanager.db")
os.environ.setdefault("BIND_HOST", "127.0.0.1")
os.environ.setdefault("BIND_PORT", "8443")
os.environ.setdefault("CLIENT_CERT_DAYS", "365")
os.environ.setdefault("CRL_VALIDITY_DAYS", "7")
os.environ.setdefault("CRL_REGEN_HOURS", "24")
os.environ.setdefault("RADIUS_HOST", "127.0.0.1")
os.environ.setdefault("RADIUS_SSH_KEY", r"C:\cmdemo\ssh_key")
os.environ.setdefault("RADIUS_SSH_USER", "crlpush")

from app.main import create_app

app = create_app()
