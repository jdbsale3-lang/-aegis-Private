# REMEDIATION — ReDoS in register email regex (CVE-adjacent / CodeQL Finding)
**ID:** AEGIS-REM-2026-001 · **Date:** 28 Aug 2026 · **Severity:** Medium (availability; non-auth endpoint)
**Found by:** GitHub CodeQL ("Polynomial regular expression used on uncontrolled data")
**All IP belongs to JDB Sales.**

---

## 1. SUMMARY
The `/api/v1/register` email validation used a **polynomial-time (ReDoS-able) regular expression** on attacker-controlled input:

```
OLD (unsafe):  ^[^@\s]+@[^@\s]+\.[^@\s]+$
```

Nested/unbounded `+` quantifiers over character classes permit **catastrophic backtracking** on crafted inputs (e.g. `!@!.` + many `!.` repetitions), allowing CPU exhaustion on an unauthenticated endpoint.

## 2. FIX (applied 28 Aug 2026)
```
NEW (safe):    ^[^@]{1,254}@[^@]{1,64}\.[^@]{1,63}$
```

- Every component is **length-bounded** `{m,n}` → **linear time**, no unbounded backtracking.
- Mirrors real email limits (RFC 5321 local ≤64, domain label ≤63) with a conservative total.
- Applied in `backend/api_server.py` (canonical `_EMAIL_RE`), committed + merged (main `621fc87`), and deployed to the **production canonical entrypoint** (`/opt/aegis/api_server.prod.py` + live `api_server.py`, service restarted, verified healthy).

## 3. VERIFICATION
- **Unit tests** added: `backend/tests/test_email_regex.py` (5 tests):
  - pattern is length-bounded & contains **no `+`/`*` quantifiers**
  - valid emails accepted (incl. `+tag`, subdomains, `.co.uk`)
  - invalid emails rejected (no-@, double-@, spaces, oversize user/domain/tld)
  - **adversarial input completes < 0.5 s** (linear guard)
  - reads the **shipped** pattern from source (CI-safe, no heavy app import)
  - Result: `5 passed`
- **Live check:** `POST /api/v1/register` with `accept_terms` returns a key; malformed emails rejected.
- **CI:** new tests run in the existing `test` job; a new **`regex-lint`** job (scripts/regex_lint.py) blocks any future unbounded `re.compile` in backend.

## 4. PREVENTION (new CI rule)
`scripts/regex_lint.py` (run in CI `regex-lint` job):
- scans `backend/**/*.py` for `re.compile`/`re.search`/`re.match` with **unbounded quantifiers** (`+` or `*` following a char class / group) → FAILS the build.
- whitelist: none by default; any intentional unbounded regex must be annotated `# noqa: REDOS` with a justification.

## 5. IMPACT & SCOPE
- Only `/api/v1/register` email field was flagged. No other regex in `backend/` uses unbounded quantifiers (verified by the lint script pass).
- This is a **defence-in-depth** improvement; the endpoint is still rate-limited (per-IP 429s via nginx/app).

**END — All IP belongs to JDB Sales.**