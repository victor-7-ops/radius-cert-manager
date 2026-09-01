"""Per-site bearer token auth for agent-facing routes (HANDOFF-FLEET.md
§4.2). Deliberately not mTLS — a site's own expiring cert would be a
chicken-and-egg problem for the very endpoint that renews it. Token is
generated at site creation, shown once, stored Argon2-hashed (reusing
app.auth's hasher), rotatable, revocable by deactivating the site.

Kept in its own dependency (not scattered through routes) so mTLS can
replace this later without touching route bodies.
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status
from sqlalchemy import select

from app import auth
from app.db import Site

TOKEN_BYTES = 32


def generate_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    return auth.hash_password(token)


def verify_token(token: str, token_hash: str) -> bool:
    return auth.verify_password(token, token_hash)


def get_current_site_factory(get_db_session):
    """Build the require_site FastAPI dependency. Agent routes must never
    accept the admin session cookie and must not be reachable by an admin
    session either — this dependency only ever looks at the Authorization
    header, so there is no cookie path into it at all."""

    def require_site(
        authorization: str | None = Header(default=None),
    ) -> Site:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing site token")
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing site token")

        db_session = get_db_session()
        # Token isn't indexable (it's hashed), so this is an O(active
        # sites) scan — fine at the planned 8-30 site scale, not fine at
        # thousands. Revisit if the fleet ever grows past that.
        for site in db_session.scalars(select(Site).where(Site.is_active.is_(True))):
            if verify_token(token, site.auth_token_hash):
                return site
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid site token")

    return require_site
