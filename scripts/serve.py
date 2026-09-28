"""Run the app under uvicorn, with optional TLS (HANDOFF-NANO-DEPLOY.md
§6): `python -m uvicorn app.main:create_app --factory` can't conditionally
add --ssl-keyfile/--ssl-certfile from a systemd ExecStart line, since
there's no shell expansion there to skip the flags when unset. This
script does it in Python instead: WEB_SSL_KEYFILE/WEB_SSL_CERTFILE unset
(the default) serves plain HTTP exactly as before; both set serves TLS.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn

from app.config import load_settings


def uvicorn_kwargs(settings) -> dict:
    kwargs = {"host": settings.bind_host, "port": settings.bind_port}
    if settings.web_ssl_keyfile and settings.web_ssl_certfile:
        kwargs["ssl_keyfile"] = str(settings.web_ssl_keyfile)
        kwargs["ssl_certfile"] = str(settings.web_ssl_certfile)
    return kwargs


def main() -> int:
    settings = load_settings()
    uvicorn.run("app.main:create_app", factory=True, **uvicorn_kwargs(settings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
