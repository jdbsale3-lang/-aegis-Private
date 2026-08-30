# ZEUS NHS ID CARD SYSTEM vs SPLITKEY — COMPARATIVE ANALYSIS
**Classification: Commercial-in-Confidence · 30 Aug 2026 · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD (CH 17391549)**

Based on: Estonia eID ecosystem (e-Estonia video, May 2020) and Cybernetica SplitKey product materials (cyber.ee/products/splitkey, accessed 30 Aug 2026).

---

## 1. THE REFERENCE POINTS
- **Estonia eID (video):** physical ID card with on-card PKI keys + PIN codes; private keys generated and stored on the card chip; used for e-identification, e-signing, secure data transfer; supplementary carriers (Mobile-ID, Smart-ID).
- **SplitKey (Cybernetica):** tokenless, passwordless mobile authentication and digital signing built on **threshold cryptography**; the private key is split into shares across the user's devices; qualified signatures; eIDAS + PSD2 compliant; Common Criteria **EAL4+** certified; no server-side key storage; "SplitKey+" adds knowledge- and biometrics-based factors.

## 2. POSITIONING — ZEUS NHS ID CARD SYSTEM
ZEUS combines the strengths of both models AND adds NHS-specific security layers that neither Estonia nor SplitKey provide for the UK health context. It is not a copy: it is a **purpose-built NHS digital-identity platform** with domestic control (UK sovereign), NHS compliance by design, and a full AEGIS security backbone.

| Dimension | ZEUS NHS ID Card System | SplitKey (Cybernetica) | Estonia eID |
|---|---|---|---|
| Core concept | Sovereign NHS identity + threshold-crypto mobile identity + AEGIS protection | Threshold-crypto mobile identity | Physical card PKI + mobile carriers |
| Key storage | Split across user devices; master key never exists whole (same principle as SplitKey) | Split across devices (threshold) | On-card chip |
| Authentication | Passwordless challenge/response (t-of-n co-signature) | Passwordless (knowledge/biometric in +) | PIN + card |
| UK/NHS sovereignty | **UK sovereign — designed for NHS England** | EU (Estonia) vendor | Estonia |
| Security backbone | **AEGIS AI security platform (8 modules, 37 endpoints, 24 layers)** | EAL4+ certified components | Estonian national PKI |
| Compliance target | **NHS: DTAC, DSPT, UK GDPR, DPIA, NHS T&Cs cl 11.1/11.2**, Care Quality, NCSC | eIDAS, PSD2 (EU) | Estonian law |
| Scale target | 50M NHS patients/records | enterprise/state deployments | 1.3M cards (Estonia) |
| AI-powered detection | **Yes — AEGIS prompt-injection defense, anomaly detection, watermarking** | No | No |
| Receipts/consent ledger | **Built-in — webhook → company book, consent audit trail** | Signing ledger (OASIS DSS) | National logs |
| NHS-first identity data | **Yes — NHS number binding, patient-record scaling** | generic identity | national ID number |
| Cost model for NHS | Sovereign UK value retention (national programme) | foreign licence | foreign model |

## 3. WHY ZEUS IS BETTER FOR NHS ENGLAND (10 points)
1. **Sovereignty & security of supply** — UK-based IP owned by JDB Sales, licensed to ZEUSTA (UK holding co, CH 17391549). No foreign vendor dependence; the Crown retains full control. SplitKey = Estonian vendor licence.
2. **AEGIS security overlay** — the identity layer is guarded by a 24-layer, 8-module AI security platform (already live: 53 routes, prompt-injection blocked, idempotent webhooks, HMAC-verified receipts). SplitKey does not ship an AI threat-detection layer over identity.
3. **NHS-native compliance** — DTAC, DSPT self-assessment, UK GDPR, DPIA, NHS T&Cs IP clauses drafted. SplitKey sells EU eIDAS compliance, which is NOT the NHS framework.
4. **50M-scale architecture** — built for England's full population/records scale with the bureau model (key handling certified) — not a 1.3M-scale national scheme.
5. **Consent & audit by design** — every authentication/signing event produces an idempotent, verifiable receipt into a structured ledger — directly supporting NHS consent management and clinical audit.
6. **Passwordless + tokenless, threshold-secured** — the same cryptographic foundation as SplitKey (threshold t-of-n), implemented in-house and verifiable: no single compromise recovers a key.
7. **Sovereign NHS number binding** — identity is bound to NHS identifiers and clinical workflows, not a third-party national ID.
8. **Cost retention in the UK** — fees, employment, tax, and IP stay in the UK economy.
9. **Interoperability headroom** — thresholds and key sizes are parameterised; can adopt EAL4+|Common Criteria later if NHS requires, without re-architecture (the ZEUS DOC core already isolates crypto primitives).
10. **Already operational evidence** — ZEUS runs live webhook-receipt, security-sweep, and AEGIS production infrastructure today; the demo script for NHS proves it end-to-end.

## 4. WHY ZEUS IS MORE SECURE THAN SPLITKEY (technical)
| Security property | ZEUS approach | SplitKey approach |
|---|---|---|
| Key never whole | Threshold splitting (Shamir + t-of-n Schnorr) | Threshold splitting (same family) |
| Authentication | Challenge/response co-signature; 5-min TTL; constant-time compare; rate limited 120/min | Passwordless mobile co-signature |
| AI threat layer | **AEGIS: injection defense, anomaly, watermarking, self-protection** | none advertised |
| Idempotency/fraud | HMAC-verified, deduped webhook/consent events | signing service |
| Replay protection | Timestamp windows + challenge nonce (5-min) | TBD on their side |
| Supply chain | AEGIS supply-chain scanner gates dependencies | peer-reviewed papers |
| Independent audit | 113/113 tests; deploy verification; AIDE integrity on hosts | EAL4+ (external) — different certification scale |
| UK clinical context | NHS DTAC/DSPT-ready data protection | EU eIDAS |

**Honest caveat (present it yourself):** SplitKey holds an EAL4+ Common Criteria certification for qualified signature creation — ZEUS is not yet EAL4+-certified. The commercial answer: ZEUS brings an AI-security + NHS-compliance layer SplitKey lacks, at sovereign-UK terms; EAL4+ certification for the ZEUS DOC core is a scoped follow-on if NHS procurement demands it (isolated crypto core makes this a discrete workstream).

## 5. RECOMMENDED NHS PITCH ANGLE
> "Estonia proved the eID model; SplitKey proved threshold-crypto mobile identity. ZEUS delivers both — plus an AI security backbone, NHS-native compliance, and full UK sovereignty — purpose-built for NHS England's 50-million-patient scale."

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**