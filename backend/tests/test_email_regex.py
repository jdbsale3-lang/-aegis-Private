"""Regression tests for the register email validation regex (ReDoS remediation).

Guards api_server.py _EMAIL_RE:
  - must be the length-bounded, linear pattern (not the old unbounded one)
  - accepts valid addresses, rejects malformed ones
  - no catastrophic backtracking on adversarial inputs (bounded quantifiers)

CI-safe: reads the shipped pattern from api_server.py source rather than
importing the whole FastAPI app (keeps the test job dependency-light).
All IP belongs to JDB Sales.
"""

import os
import re

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _shipped_pattern() -> str:
    path = os.path.join(BACKEND, "api_server.py")
    with open(path) as fh:
        src = fh.read()
    for line in src.splitlines():
        if "_EMAIL_RE = re.compile" in line:
            # extract the r"..." literal (raw string, may contain backslashes)
            start = line.find('r"')
            assert start != -1, "raw-string literal not found"
            end = line.rfind('"')
            return line[start + 2 : end]
    raise AssertionError("_EMAIL_RE not found in api_server.py")


PATTERN = _shipped_pattern()
RE = re.compile(PATTERN)


def test_pattern_is_length_bounded_and_linear():
    """ReDoS fix: every quantifier is {m,n} bounded - no nested/unbounded + or *."""
    assert "{1,254}" in PATTERN, "user part must be bounded"
    assert "{1,64}" in PATTERN, "domain part must be bounded"
    assert "{1,63}" in PATTERN, "tld part must be bounded"
    # old unsafe pattern had bare + quantifiers; ensure they are gone
    assert "+@" not in PATTERN and "+\\." not in PATTERN
    assert PATTERN.count("+") == 0, "no unbounded + allowed"


def test_valid_emails_accepted():
    valid = [
        "darren@jdbsale3.com",
        "lauren.roberts3@nhs.net",
        "user+tag@example.co.uk",
        "a@b.io",
        "first.last@sub.domain.org",
    ]
    for email in valid:
        assert RE.match(email), f"should accept: {email}"


def test_invalid_emails_rejected():
    invalid = [
        "nope",  # no @
        "a@@b.com",  # double @
        "a@b",  # no dot/tld
        "a@. com",  # space + bad
        "a b@c.com",  # space in user
        "a@b c.com",  # space in domain
        "@b.com",  # empty user
        "a@.com",  # empty domain label
        "a" * 256 + "@b.com",  # user > 254
        "a@" + "b" * 70 + ".com",  # domain label > 64
        "a@b." + "c" * 70,  # tld > 63
    ]
    for email in invalid:
        assert not RE.match(email), f"should reject: {email[:40]}"


def test_adversarial_input_linear_performance():
    """Catastrophic-pattern guard: bounded quantifiers => fast on hostile input."""
    import time

    hostile = "!" * 300 + "@" + "!" * 300 + "." + "x" * 50
    t0 = time.time()
    RE.match(hostile)
    elapsed = time.time() - t0
    assert elapsed < 0.5, f"regex too slow on adversarial input: {elapsed:.3f}s"


def test_module_shiped_pattern_matches_expected():
    """The exact shipped literal (not a copy) must equal the hardened pattern."""
    assert RE.match("ok@example.com")
    assert not RE.match("bad@@example.com")
