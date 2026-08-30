# ZEUS DOC — SECURITY WHITEPAPER
**Version 1.0 · 30 Aug 2026 · Commercial-in-Confidence · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD**

## 1. THREAT MODEL
ZEUS DOC protects against: key exfiltration (no single device holds a key), credential phishing (no passwords), replay (short-TTL challenges), device theft (threshold ≤ n-1 devices still can't authenticate), insider abuse (t-of-n quorum + audit receipts), supply-chain tampering (pure-Python, dependency-light core; AEGIS supply-chain scanner).

## 2. DEFENCE-IN-DEPTH LAYERS
| Layer | Control |
|---|---|
| 1 | Zero knowledge: master key split (Shamir) and destroyed; no party ever holds the whole key |
| 2 | Threshold quorum: t-of-n partial signatures required for auth and signing |
| 3 | Tokenless & passwordless: no shared secrets, no OTP, no bearer tokens |
| 4 | Challenge freshness: random 32-byte nonce, TTL 300s, constant-time comparison |
| 5 | Cryptographic verification: every signature validated against the registered public key |
| 6 | Tamper resistance: any modification of the signed document fails verification |
| 7 | Platform guardrail: AEGIS production stack — prompt-injection defense, anomaly detection, watermarking, self-protection scans (8 modules, 37 endpoints) |
| 8 | Receipt integrity: HMAC-verified, idempotent event receipts (dedupe by event id) |
| 9 | Operational hygiene: rate limits (120/min), admin-gated management endpoints, journaled AIDE integrity checks |
| 10 | Governance: UK sovereign IP, NHS compliance pack (DTAC/DSPT/UK GDPR/DPIA), IP clause drafts |

## 3. CRYPTOGRAPHIC JUSTIFICATION
- **Shamir (t, n):** information-theoretic secret sharing — with k < t shares, no information about the secret exists (mathematically). Reference: Shamir, A., "How to Share a Secret" (1979).
- **Threshold Schnorr:** partial signatures combine via Lagrange interpolation over the group order; verification uses the aggregate public key — the security reduces to the discrete-log assumption on secp256k1.
- **Nonce determinism:** per-device nonce derived via HMAC(share-id, document) — reproducible audit trail without reusing nonces across documents.
- All arithmetic is pure-Python and auditable line-by-line (no third-party crypto library opacity for the core).

## 4. NHS-SPECIFIC ASSURANCE (mapped to compliance asks)
| Ask | Evidence in ZEUS |
|---|---|
| DTAC (Digital Technology Assessment Criteria) | Data protection, clinical safety, interoperability, accessibility posture — mapped in compliance pack |
| DSPT (Data Security & Protection Toolkit) | Self-assessment completed; 10 data-security standards tracked |
| UK GDPR Art.9 (health data) | Consent ledger with per-event receipts; DPIA drafting |
| NHS Terms & Conditions 11.1/11.2 | Background IP clause drafted (contract pack) |
| NCSC-aligned | Passwordless + threshold aligns with NCSC guidance on modern authentication |
| Audit trail | Every auth/sign event produces a deduplicated, verify-able receipt |

## 5. KNOWN LIMITATIONS & MITIGATIONS
- **No EAL4+ certification yet** (SplitKey has it). Mitigation: crypto core is isolated; a scoped Common Criteria workstream is a follow-on if procurement demands it. We lead on AI-threat-layer and NHS-native compliance, which SplitKey does not offer.
- **Pure-Python performance** is adequate for auth/signing volumes (reference build); production path can swap EC ops for a constant-time library behind the same interface.
- **File-based IdentityStore** in reference build → production uses the AEGIS Postgres backend with key-wrapping.

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**