# ZEUS DOC
**Digital Operations & Certificates** — ZEUSTA's own tokenless, passwordless authentication and digital-signing software.
The identity backbone of the ZEUS NHS ID Card System. All IP belongs to JDB Sales; licensed to ZEUSTRUSTAEGISSECURITY LTD.

## Why
Passwords are a costly, insecure relic. ZEUS DOC delivers hardware-grade security in software via threshold cryptography:
- **No tokens.** No passwords. No OTP.
- Master key **split** across devices (Shamir t-of-n); never exists whole, anywhere.
- Authentication and signatures require a **quorum** of the user's own devices (t-of-n co-signature).
- Legally-strong non-repudiation for documents and consent records.

## Quick start
```bash
pip install fastapi pydantic uvicorn
python -m zeus_doc.api            # FastAPI on :8400 (ZEUS_DOC_STORE, PORT env)
python -m pytest tests/ -v        # 15/15 tests
```

## Docs
- `docs/ZEUS-DOC-TECH-SPEC.md` — architecture, crypto core, API surface
- `docs/ZEUS-DOC-SECURITY-WHITEPAPER.md` — threat model, defences, NHS assurance
- `docs/ZEUS-DOC-NHS-PROPOSITION.md` — NHS England pitch + 1-Oct demo script
- `docs/ZEUS-DOC-IP-PROTECTION.md` — trademarks, patent strategy, assignment
- `docs/ZEUS-NHS-vs-SPLITKEY-COMPARISON.md` — how we beat the reference designs

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**