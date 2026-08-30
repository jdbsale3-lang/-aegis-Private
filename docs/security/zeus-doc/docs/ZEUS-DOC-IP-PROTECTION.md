# ZEUS DOC — IP PROTECTION & ASSIGNMENT PACK
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD (CH 17391549)**

## 1. IP MAP (what we own)
| Asset | Type | Owner → Licensee |
|---|---|---|
| ZEUS DOC software (source, crypto core, API) | Copyright + trade secret | JDB Sales → ZEUSTA (royalty-bearing licence) |
| "ZEUS DOC" / "ZEUS" / "AEGIS" / "ZEUSTA" marks | UK Trademarks (to file) | JDB Sales → ZEUSTA |
| Threshold-crypto signing method (t-of-n Schnorr + Shamir split-Auth) | Patentable (consider) | JDB Sales |
| NHS ID Card System architecture (50M, bureau model) | Trade secret + design | JDB Sales → ZEUSTA |
| Docs, whitepapers, pitch, comparison | Copyright | JDB Sales |

## 2. TRADEMARK APPLICATIONS (UK IPO — draft, £205 + £60/class per mark)
**Mark: ZEUS DOC** — one application, classes:
- Class 9 (software; download/electronic ID) — core
- Class 42 (SaaS, authentication, digital-signing services) — core
- Class 45 (online identity verification services) — strategic
Estimated: £205 filing + £60 × 3 classes = **£385** (single mark).
Review series-option (ZEUS/ZEUS AI/ZEUS DOC) with IPO guidance — series filings at risk of refusal (~40% series refusal); file ZEUS DOC standalone first, ZEUS separately if budget allows.

## 3. PATENT STRATEGY (UK IPO — consider, medium priority)
**Candidate:** "Method and system for threshold-cryptographic passwordless authentication and co-signing with per-device deterministic nonces for audit integrity."
- Novel angle vs SplitKey's published work: **deterministic per-device nonce derivation (HMAC(share_id, document))** producing reproducible partial signatures tied to the audit ledger — a concrete implementation detail worth a freedom-to-operate + novelty review.
- Cost: UK patent ~£4k–£8k filed/attorney; deferred via provisional filing (~£50 search, then within 12 months file full).
- Recommendation: file **UK provisional** to secure the priority date; keep source and docs flagged Trade Secret until filed (do not publish before filing — the whitepaper stays Commercial-in-Confidence).

## 4. IP ASSIGNMENT / LICENCE (deed drafted in account pack)
- IP Copyright Assignment: **JDB Sales → ZEUSTA** (or licence) to be executed — template exists in the contract pack (`IP-Licence-Agreement.docx`); update to reference ZEUS DOC + NHS ID Card System + ZEUSTA brand.
- Protect in NHS contract: NHS T&Cs cl 11.1/11.2 background-IP analysis drafted; ensure ZEUS DOC remains Background IP with licence grants scoped to the programme.

## 5. OPERATIONAL PROTECTION
1. Source in private repo `jdbsale3-lang/-aegis-Private` (branch-protected, 7 checks + review).
2. Secrets never in code — keys in env/systemd drop-ins (mode 600).
3. Whitepaper & source flagged Commercial-in-Confidence — never publish pre-filing.
4. AIDE integrity on hosts, idempotent webhooks, HMAC-verified receipts — evidence trail.
5. Every NHS-facing doc ends: **All IP belongs to JDB Sales.**

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**