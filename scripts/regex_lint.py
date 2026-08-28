#!/usr/bin/env python3
"""AEGIS regex lint — ReDoS guard for the CI pipeline.

Fails the build if any re.compile/re.search/re.match in backend/ uses an
unbounded quantifier (+, *, or {m,} ) on a character class or group, which
is the classic catastrophic-backtracking (ReDoS) shape.

Usage:  python3 scripts/regex_lint.py
Exit 0 = clean · exit 1 = violations found. All IP belongs to JDB Sales.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # repo root
BACKEND = ROOT / "backend"

# Unbounded quantifier right after a class/group/closing: e.g. [a-z]+  (a+)
UNBOUNDED = re.compile(r"(\([^)]*\)|\[[^\]]*\]|\)|\])\s*(\+|\*|\{\d+,\})")

# Allow an explicit noqa comment on the same line for intentional cases.
VIOLATIONS = []


def lint_file(path: Path) -> int:
    count = 0
    for lineno, raw in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1
    ):
        if re.search(r"re\.(compile|search|match|fullmatch|findall|sub)\(", raw):
            if "# noqa: REDOS" in raw:
                continue
            m = UNBOUNDED.search(raw)
            if m:
                VIOLATIONS.append(
                    f"{path.relative_to(ROOT)}:{lineno}: {raw.strip()[:90]}"
                )
                count += 1
    return count


def main() -> int:
    if not BACKEND.is_dir():
        print(f"ERROR: backend dir not found at {BACKEND}")
        return 1
    total = 0
    for py in sorted(BACKEND.rglob("*.py")):
        total += lint_file(py)
    if total:
        print(f"REDOS-LINT: {total} unbounded-quantifier regex(es) found:")
        for v in VIOLATIONS:
            print("  " + v)
        print(
            "Fix: make quantifiers bounded ({m,n}); add '# noqa: REDOS' only with justification."
        )
        return 1
    print("REDOS-LINT: OK - no unbounded regex quantifiers in backend/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
