"""Hub self-monitoring (HANDOFF-FLEET.md §8.2): the liveness route and
the heartbeat ping fleet_watch sends on a successful run. Both must stay
independent of the app's own alert_webhook_url."""

from fastapi.testclient import TestClient

from app import pki
from app.main import create_app


def _write_throwaway_pki(app_settings, throwaway_pki):
    inter_dir = app_settings.pki_path
    (inter_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (inter_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )


def test_liveness_route_404s_when_no_token_configured(app_settings, throwaway_pki):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app_settings.liveness_token = None
    app = create_app(app_settings)
    client = TestClient(app)

    resp = client.get("/api/live/anything")
    assert resp.status_code == 404


def test_liveness_route_404s_on_wrong_token(app_settings, throwaway_pki):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app_settings.liveness_token = "correct-token"
    app = create_app(app_settings)
    client = TestClient(app)

    resp = client.get("/api/live/wrong-token")
    assert resp.status_code == 404


def test_liveness_route_200s_on_correct_token_with_no_auth(app_settings, throwaway_pki):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app_settings.liveness_token = "correct-token"
    app = create_app(app_settings)
    client = TestClient(app)

    resp = client.get("/api/live/correct-token")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_heartbeat_not_sent_when_url_unset(app_settings, throwaway_pki, monkeypatch):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app_settings.heartbeat_url = None
    app = create_app(app_settings)

    calls = []
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: calls.append(1))

    app.state.send_heartbeat()
    assert not calls


def test_heartbeat_pings_configured_url(app_settings, throwaway_pki, monkeypatch):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app_settings.heartbeat_url = "https://hc-ping.example/abc123"
    app = create_app(app_settings)

    captured = {}

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResponse()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    app.state.send_heartbeat()
    assert captured["url"] == "https://hc-ping.example/abc123"


def test_heartbeat_failure_does_not_raise(app_settings, throwaway_pki, monkeypatch):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app_settings.heartbeat_url = "https://hc-ping.example/abc123"
    app = create_app(app_settings)

    import urllib.request

    def raising_urlopen(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", raising_urlopen)

    app.state.send_heartbeat()  # must not raise
