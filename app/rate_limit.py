"""Simple in-process sliding-window rate limiter.

Matches the rest of this app's in-memory-state pattern (pending
bundles/previews/batches in main.py) — no Redis, no cross-process
sharing, resets on restart. That's fine for what this guards: bulk
CSV export and .p12/bundle downloads, where the goal is slowing down
scraping/enumeration from a single admin session or IP, not surviving
a multi-worker deployment.
"""

from __future__ import annotations

import time

_buckets: dict[str, list[float]] = {}

# Distinct keys (IP/session ids), not request counts per key, is what grows
# unbounded here — a key whose bucket empties out and is never checked
# again still sits in the dict forever. Sweep it out periodically rather
# than on every call, so cost stays amortized instead of O(all keys) per
# request.
_SWEEP_INTERVAL_SECONDS = 300
_last_sweep = 0.0


def _sweep_stale(now: float) -> None:
    global _last_sweep
    if now - _last_sweep < _SWEEP_INTERVAL_SECONDS:
        return
    _last_sweep = now
    for stale_key in [k for k, v in _buckets.items() if not v]:
        del _buckets[stale_key]


def is_rate_limited(key: str, max_requests: int, window_seconds: float) -> bool:
    """True if `key` has already made max_requests within the last
    window_seconds (and this call does NOT count against it); False
    otherwise (and this call DOES count against it, i.e. the caller is
    expected to actually perform the request it's checking for)."""
    now = time.monotonic()
    bucket = _buckets.setdefault(key, [])
    cutoff = now - window_seconds
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)
    if len(bucket) >= max_requests:
        _sweep_stale(now)
        return True
    bucket.append(now)
    _sweep_stale(now)
    return False
