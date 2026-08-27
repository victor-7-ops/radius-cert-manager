import re

CN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$")

# Accepts the common separator styles (colon, dash, dotted-quad, or none)
# and normalizes to colon-separated lowercase — the format everything
# else (FreeRADIUS logs, switch/AP MAC-auth tables) expects.
MAC_RE = re.compile(
    r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
    r"|^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$"
    r"|^[0-9A-Fa-f]{12}$"
)


def normalize_mac(raw: str) -> str | None:
    """Return a colon-separated lowercase MAC, or None if raw doesn't
    match a recognized MAC format."""
    if not MAC_RE.match(raw):
        return None
    hex_only = re.sub(r"[:.\-]", "", raw).lower()
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))
