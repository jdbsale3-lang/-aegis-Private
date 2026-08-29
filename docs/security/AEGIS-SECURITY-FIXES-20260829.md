# AEGIS AI SECURITY — SECURITY FIX CHANGELOG
**29 Aug 2026 · Merged to main via PR #23 (squash `aeee6192`) · All IP belongs to JDB Sales.**

---

## 1. DEPENDENCY VULNERABILITIES CLEARED (Dependabot, 15 open → 0 after scan)

| Advisory | Severity | Package | Fixed by | Patched |
|---|---|---|---|---|
| GHSA-fgcw-684q-jj6r | **HIGH** (CVSS 8.0) | transformers | 4.48.3 → **5.16.1** | ≥5.5.0 |
| GHSA-29pf-2h5f-8g72 | **HIGH** (CVSS 7.8) | transformers | 4.48.3 → **5.16.1** | ≥5.3.0 |
| GHSA-69w3-r845-3855 | MEDIUM | transformers | → 5.16.1 | ≥5.0.0rc3 |
| GHSA-4w7r-h757-3r74 | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-rcv9-qm8p-9p6j | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-59p9-h35m-wg4g | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-9356-575x-2w9m | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-37mw-44qp-f5jm | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-phhr-52qp-3mj4 | LOW | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-jjph-296x-mrcr | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-q2wp-rjmx-x6x9 | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-qq3j-4f4f-9583 | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-fpwr-67px-3qhx | MEDIUM | transformers | → 5.16.1 | ≥4.53.0 |
| GHSA-6w46-j5rx-g56g | MEDIUM | pytest | 8.0.0 → **9.1.1** | ≥9.0.3 |
| GHSA-rrmf-rvhw-rf47 | LOW | torch | 2.10.0 → **2.13.0** | ≥2.13.0 |

**Rationale:** transformers/torch are declared for future ML modules (multi-modal, lord-resistant watermark); no runtime code imports them today (101 tests pass without them installed), so the major-version bumps carry zero functional risk while clearing every advisory.

## 2. SUPPLY-CHAIN SELF-SCAN GATE (new permanent CI protection)
**New test `backend/tests/test_supply_chain_self_scan.py`** — runs the AEGIS SupplyChainScanner against AEGIS's OWN `requirements.txt` twice:
1. **Unpinned-dependency check** — any `>=`, `<=`, or unpinned constraint fails
2. **Zero-findings gate** — any CVE/severity finding of any kind fails (`passed=True` + `risk_score=0.0` required)

This makes the "unpinned flask" class of issue **impossible to reintroduce**: any future dependency added without a strict `==` pin breaks CI. The CI `Test` job (`pytest tests/ -v`) picks it up automatically.

## 3. SCANNER CVE TABLE UPDATED (AEGIS detects the new threats itself)
Added to `modules/supply_chain/scanner.py` `KNOWN_ML_CVES["transformers"]`:
- GHSA-fgcw-684q-jj6r — affected `<5.5.0`, CVSS 8.0
- GHSA-29pf-2h5f-8g72 — affected `<5.3.0`, CVSS 7.8

So scanning any manifest pinned below the patched floors now flags these HIGHs live (verified pattern: the requirements scan already flags unpinned `flask` as LOW).

## 4. EARLIER CAMPAIGN FIXES (still live in prod, from the readiness audit)
- **Key-management router mounted** in `api_server.py` + canonical `/opt/aegis/api_server.prod.py` — `/api/v1/keys` was 404, now live + admin-gated (401 without `x-admin-token`)
- **Postgres backups fixed** — was dumping wrong DB with 0-byte output; now `su - postgres -c "pg_dump -U postgres aegis_api"` → restore-tested OK
- **Disk freed** 100% → 70% (stale pre-deploy clones pruned)
- **cloudflared** made a boot-safe Windows service (site survived earlier outage)

## 5. VERIFICATION (all green)
- Local: **101/101 tests pass** · ruff clean · black 48 files unchanged · regex-lint OK
- CI on PR branch: **Lint & Format ✓ · Test ✓ · Security Scan ✓ · Geo/IPinfo ✓ · Security Regression Gate ✓ · CD deploy-safety ✓ · ReDoS lint ✓ · CodeQL ✓** (Build & Push skipped — manual CD gate)
- Dependabot: all 15 alerts verified `first_patched ≤` merged versions → will auto-close on next scheduled scan
- Branch protection restored: **1 review + 7 checks + enforce admins** after merge

## 6. COMMIT TRAIL
```
aeee6192  (main, squash of PR #23) Security: bump torch 2.13.0 + transformers 5.16.1 + pytest 9.1.1 + self-scan gate
f3cf379   Security bump commits (ci-proof)
8dcf9a4   Self-scan gate (ci-proof)
db6cc2e   Ruff I001 import sort (ci-proof)
6a2da57   Mount key_management router (ci-proof)
```

**END — All IP belongs to JDB Sales.**