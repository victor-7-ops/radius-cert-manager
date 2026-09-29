from __future__ import annotations

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


def normalize_employee_key(name: str | None) -> str | None:
    """Casefold + collapse-whitespace + trim, so "Juan Dela Cruz",
    "juan dela cruz" and "  Juan  Dela Cruz " all key the same employee
    (HANDOFF-LIFECYCLE.md §1.1). employee_name stays free text as the
    display value — this is only ever used to derive the indexed,
    comparable employee_key column. Deliberately NOT fuzzy (no edit
    distance, no dropping middle initials) — a revoke-all keyed on a
    guess is worse than one that misses, since it can disable someone
    still employed. Returns None for empty/None input."""
    if not name:
        return None
    collapsed = re.sub(r"\s+", " ", name.strip())
    return collapsed.casefold() or None


def normalize_mac(raw: str) -> str | None:
    """Return a colon-separated lowercase MAC, or None if raw doesn't
    match a recognized MAC format."""
    if not MAC_RE.match(raw):
        return None
    hex_only = re.sub(r"[:.\-]", "", raw).lower()
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))
