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
        return True
    bucket.append(now)
    return False
