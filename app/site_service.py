"""Site registry mutations — create, rotate token, deactivate. Admin-side
counterpart to app/site_auth.py's agent-side verification."""

from __future__ import annotations

from dataclasses import dataclass
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db, site_auth


class SiteCNConflictError(Exception):
    pass


@dataclass
class CreateSiteResult:
    site: db.Site
    token: str  # shown once — caller must display and discard, never persisted in plaintext


def create_site(
    session: Session,
    name: str,
    radius_cn: str,
    actor: str,
    subsidiary: str | None = None,
    address: str | None = None,
    crl_validity_days: int = 30,
    checkin_interval_seconds: int = 3600,
    notes: str | None = None,
) -> CreateSiteResult:
    existing = session.scalar(select(db.Site).where(db.Site.radius_cn == radius_cn))
    if existing is not None:
        raise SiteCNConflictError(f"a site with radius_cn={radius_cn!r} already exists")

    token = site_auth.generate_token()
    site = db.Site(
        name=name,
        radius_cn=radius_cn,
        subsidiary=subsidiary,
        address=address,
        auth_token_hash=site_auth.hash_token(token),
        crl_validity_days=crl_validity_days,
        checkin_interval_seconds=checkin_interval_seconds,
        notes=notes,
    )
    session.add(site)
    session.commit()
    session.refresh(site)
    db.audit(
        session, actor=actor, action="site_create", target=radius_cn, detail=f"name={name}",
        subsidiary=site.subsidiary, site_id=site.id,
    )
    session.commit()
    return CreateSiteResult(site=site, token=token)


def rotate_token(session: Session, site: db.Site, actor: str) -> str:
    token = site_auth.generate_token()
    site.auth_token_hash = site_auth.hash_token(token)
    db.audit(
        session, actor=actor, action="site_rotate_token", target=site.radius_cn,
        subsidiary=site.subsidiary, site_id=site.id,
    )
    session.commit()
    return token


def deactivate(session: Session, site: db.Site, actor: str) -> None:
    site.is_active = False
    db.audit(
        session, actor=actor, action="site_deactivate", target=site.radius_cn,
        subsidiary=site.subsidiary, site_id=site.id,
    )
    session.commit()


def reactivate(session: Session, site: db.Site, actor: str) -> None:
    site.is_active = True
    db.audit(
        session, actor=actor, action="site_reactivate", target=site.radius_cn,
        subsidiary=site.subsidiary, site_id=site.id,
    )
    session.commit()


def set_vlan_segmentation(session: Session, site: db.Site, enabled: bool, actor: str) -> None:
    """Toggles whether this site's RADIUS adapter assigns VLANs at all.

    Off for sites that are only router + FreeRADIUS + AP, with no managed/
    L3 switch to honor an 802.1Q trunk -- authentication still happens
    (Access-Accept/Reject), just without any Tunnel-* VLAN attributes.
    Takes effect on the site's next policy pull, not immediately (the
    adapter only ever reads its locally cached, signed policy.json).
    """
    site.vlan_segmentation_enabled = enabled
    db.audit(
        session, actor=actor,
        action="site_vlan_segmentation_enable" if enabled else "site_vlan_segmentation_disable",
        target=site.radius_cn, subsidiary=site.subsidiary, site_id=site.id,
    )
    session.commit()
