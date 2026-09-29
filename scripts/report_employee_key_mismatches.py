"""Report employee_name spellings that collide or nearly collide on
employee_key (HANDOFF-LIFECYCLE.md §1.1). Read-only — reports, never
auto-merges: merging two employees' certificates under one identity is a
human decision, and a revoke-all built on a wrong guess can disable
someone still employed.

Two kinds of finding:

1. EXACT KEY COLLISIONS — two or more distinct employee_name spellings
   (e.g. "Juan Dela Cruz" / "juan dela cruz") that already normalize to
   the same employee_key. These are almost certainly the same person and
   are already grouped correctly for offboarding purposes; listed here
   so a human can see (and optionally clean up) the display-spelling
   drift.
2. NEAR-MISS KEYS — employee_keys that are textually very close but not
   identical (e.g. "juan dela cruz" / "juan delacruz"), which may be the
   same person entered two different ways, or may be two different
   people who happen to share a similar name. This is a coarse
   similarity heuristic (difflib), not a judgment — every pair needs a
   human look, and this script never merges anything.
"""

import difflib
import sys
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select

from app import db
from app.main import create_app

# Two distinct keys with a similarity ratio at or above this are flagged
# as a near-miss. 0.90 catches a dropped/added space or a single typo'd
# character in a short name without flooding the report with unrelated
# short names that happen to share common substrings.
NEAR_MISS_THRESHOLD = 0.90


def main() -> int:
    app = create_app()
    session = app.state.get_db_session()

    rows = session.execute(
        select(db.Certificate.employee_key, db.Certificate.employee_name)
        .where(db.Certificate.employee_key.is_not(None))
        .distinct()
    ).all()

    by_key: dict[str, set[str]] = {}
    for key, name in rows:
        by_key.setdefault(key, set()).add(name)

    collisions = {k: names for k, names in by_key.items() if len(names) > 1}
    print(f"Exact key collisions (same employee_key, different spelling): {len(collisions)}")
    for key, names in sorted(collisions.items()):
        print(f"  employee_key={key!r}:")
        for name in sorted(names):
            count = session.scalar(
                select(func.count()).select_from(db.Certificate).where(
                    db.Certificate.employee_name == name
                )
            )
            print(f"    {name!r} ({count} certificate(s))")

    keys = sorted(by_key)
    near_misses = []
    for a, b in combinations(keys, 2):
        ratio = difflib.SequenceMatcher(None, a, b).ratio()
        if ratio >= NEAR_MISS_THRESHOLD:
            near_misses.append((ratio, a, b))
    near_misses.sort(reverse=True)

    print(f"\nNear-miss keys (similar but not identical): {len(near_misses)}")
    for ratio, a, b in near_misses:
        print(f"  {ratio:.2f}  {a!r}  vs  {b!r}")

    print(
        f"\n{len(collisions)} exact collision group(s), {len(near_misses)} near-miss pair(s). "
        "Nothing was changed — this is a report only."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
