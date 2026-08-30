# ZEUS DOC — TECHNICAL SPECIFICATION
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD**

## 1. WHAT ZEUS DOC IS
**ZEUS DOC (Digital Operations & Certificates)** is ZEUSTA's own tokenless, passwordless authentication and digital-signing software — the identity backbone of the ZEUS NHS ID Card System. It is our sovereign answer to Cybernetica SplitKey: threshold cryptography in pure Python, no external crypto dependencies, fully auditable.

## 2. ARCHITECTURE
```
┌────────────┐      ┌──────────────────────────────┐      ┌─────────────────┐
│ Device 1..n │──shares──▶│  ZEUS DOC Service (FastAPI) │◀──challenge──│  Verifier / NHS  │
│ (mobile/app)│─partials─▶│  - IdentityStore (file)     │──receipt─────│  (trust anchor)  │
└────────────┘            │  - ThresholdSigner          │      └─────────────────┘
                          │  - AEGIS integration hooks  │
                          └──────────────────────────────┘
```
Components (package `zeus_doc/`):
- `core.py` — field arithmetic (secp256k1 prime field), EC point ops, Shamir secret sharing, threshold Schnorr (t-of-n).
- `identity.py` — IdentityStore (create/issue/verify), passwordless challenge/response, document signing.
- `api.py` — FastAPI REST service (`/v1/identities*`, `/v1/identities/{id}/challenge|authenticate|sign|verify`, `/health`).

## 3. CRYPTOGRAPHIC CORE
- Domain: secp256k1 curve parameters (P, N, G) — generic choice, auditable pure-Python EC arithmetic.
- **Shamir secret sharing** over GF(P): `split(secret, t, n)` → n shares; `reconstruct(any_t_shares)` → secret (Lagrange interpolation). Verified in tests.
- **Threshold Schnorr signatures (t-of-n):** each device holds a share (x_id, y_share) and its own ephemeral nonce; the verifier/coordinator combines ≥t partial signatures into a full (R, s) signature valid against the aggregate public key dG. Deterministic per-device nonce (HMAC of share-id + document) for audit reproducibility.
- **Passwordless authentication:** server issues a random challenge (hex, 5-min TTL, constant-time compare); the user's t devices co-sign the challenge; verification succeeds iff signature verifies against the registered public key. No passwords, no OTP, no tokens.
- **Non-repudiation signing:** same t-of-n machinery signs document bytes; signature verified against the identity public key with full R-point carried (no y-parity loss).

## 4. API SURFACE
| Method | Path | Purpose |
|---|---|---|
| GET | /health | service health |
| POST | /v1/identities | create identity; master key split & wiped (`shares_wiped:true`) |
| GET | /v1/identities/{id} | identity summary (public key, devices — no secrets) |
| POST | /v1/identities/{id}/challenge | issue authentication challenge (5-min TTL) |
| POST | /v1/identities/{id}/authenticate | passwordless t-of-n co-signature auth |
| POST | /v1/identities/{id}/sign | sign a document (base64), returns rx, ry, s |
| POST | /v1/identities/{id}/verify | verify a signature |

## 5. SECURITY PROPERTIES
- Master key never stored whole — split at creation, original destroyed.
- Challenge TTL 5 min; replay rejected; constant-time compare on challenge.
- Threshold enforces quorum: fewer than t devices cannot authenticate or sign.
- Tamper detection: altered documents fail verification.
- Rate limiting + HMAC-verified receipts available via the AEGIS production stack (integration hook).
- Idempotency: receipt/consent events dedupe by event id (proven pattern).

## 6. DEPLOYMENT
```
pip install -r requirements.txt   # fastapi, pydantic, uvicorn only
ZEUS_DOC_STORE=/var/lib/zeus-doc/store.json PORT=8400 python -m zeus_doc.api
systemd unit + reverse proxy (nginx) recommended; AEGIS middleware for auth-gating management endpoints.
```

## 7. TEST EVIDENCE
`tests/test_zeus_doc.py` — 15 tests, all pass:
Shamir split/reconstruct · insufficient shares · t-of-n Schnorr (2-of-3, 3-of-5, 2-of-2, 4-of-5, 3-of-3) · tampered-message rejection · wrong-pubkey rejection · passwordless auth success · wrong challenge · insufficient devices · sign/verify roundtrip · master-key-never-stored · full REST flow.

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**