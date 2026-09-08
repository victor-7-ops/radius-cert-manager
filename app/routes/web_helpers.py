"""Shared helpers for the server-rendered UI routes (app/routes/web*.py).

Pure functions with no dependency on request-scoped state — split out so
every web_*.py module can import the same implementation instead of each
carrying its own copy.
"""

from __future__ import annotations

import datetime
import urllib.parse

import qrcode
import qrcode.image.svg
from fastapi import HTTPException, status

from app import db


def flash(url: str, message: str, kind: str = "success") -> str:
    """Append a one-shot flash message to a redirect URL. base.html reads
    ?flash=/&flash_kind= on load, shows a toast, then strips the params
    from the address bar via history.replaceState — so a refresh doesn't
    re-show it and the URL doesn't stay ugly."""
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}flash={urllib.parse.quote(message)}&flash_kind={kind}"


def qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    return img.to_string(encoding="unicode")


def relative_expiry(expires_at: datetime.datetime) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    delta = expires_at - now
    days = delta.days
    if days < 0:
        return "expired"
    if days == 0:
        return "today"
    return f"in {days} days"


def effective_status(cert: db.Certificate) -> str:
    if cert.status == db.CertStatus.active and cert.is_expired():
        return "expired"
    return cert.status.value if hasattr(cert.status, "value") else cert.status


def ca_expiry_warnings(deps, now: datetime.datetime) -> list[str]:
    warnings = []
    for label, cert in (("Intermediate CA", deps.inter_cert), ("Root CA", deps.root_cert)):
        if cert is None:
            continue
        not_after = cert.not_valid_after_utc
        if not_after - now <= datetime.timedelta(days=180):
            warnings.append(f"{label} expires {not_after.date()}")
    return warnings


def dir_size_bytes(path) -> int:
    total = 0
    if path.exists():
        for f in path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    return total


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def require_cert_scope(admin: db.Admin, cert: db.Certificate) -> None:
    """A subsidiary-scoped admin can only act on certs for their own
    company. Unscoped admins (subsidiary_scope is None/blank) are
    unrestricted, same as before this feature existed."""
    if admin.subsidiary_scope and cert.subsidiary != admin.subsidiary_scope:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not permitted for this subsidiary")


def require_unscoped(admin: db.Admin, detail: str) -> None:
    if admin.subsidiary_scope:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)
