# ZEUS DOC — OPERATIONS RUNBOOK
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD**

## 1. SERVICE
```
ZEUS_DOC_STORE=/var/lib/zeus-doc/store.json PORT=8400 python -m zeus_doc.api
```
systemd unit (`zeus-doc.service`), reverse-proxied behind nginx on a TLS-terminating host (recommended: alongside AEGIS at apiaegissecurity.tech path or its own subdomain). All management endpoints gated by AEGIS middleware (API-key + rate limit 120/min).

## 2. HEALTH & MONITORING
- `GET /health` → `{"status":"ok"}` — wire into the same monitor as `/health` checks (uptime probe).
- Verify store writable: `test -w /var/lib/zeus-doc/store.json`.
- Disk/log rotation: store JSON daily-backup (time-stamped), keep 30d.

## 3. FAILURE MODES & REMEDIATION
| Symptom | Cause | Fix |
|---|---|---|
| 500 on identity create | store path not writable | fix perms/service user; check disk |
| Auth fails for valid devices | challenge expired (>300s) or repeated | re-issue challenge (client side) |
| Signature verify false | document bytes changed after signing | re-sign from devices; compare hashes |
| Store corrupt JSON | crash mid-write | restore latest backup; replay identity creation |
| Service down | port/venv error | journal + restart; verify with `/health` |

## 4. OPS RHYTHM
- **Daily:** health probe, store backup check.
- **Weekly:** test suite run (15 tests); compare partial-signature logs vs store for anomalies.
- **Monthly:** AIDE integrity on host; rotate signing keys test identities; review receipts ledger (consent audit).
- **Quarterly:** re-issue test identity + threshold combos; update whitepaper/spec against changes.

## 5. NHS DEMO CHECKLIST (pre-meeting)
- [ ] service up, /health ok
- [ ] create demo identity (2-of-3), screenshot flow
- [ ] challenge → authenticate → sign consent doc → verify (all 200)
- [ ] tamper case: verify modified doc fails (show honesty)
- [ ] AEGIS /stats live + injection demo ready
- [ ] receipt pipeline (webhook → Sheets) live
- [ ] comparison + IP pack printed

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**