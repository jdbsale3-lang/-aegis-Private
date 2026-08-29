# AEGIS AI SECURITY — DTAC SUBMISSION ANSWERS (DRAFT)
**For: NHS England Digital Technology Assessment Criteria (refreshed form, live 6 April 2026) · All IP belongs to JDB Sales.**
Mapping to AEGIS evidence. Items marked **[PENDING]** need action before submission; everything else is factual per verified production state.

---

## A. PRODUCT & SUPPLIER DETAILS
| Field | Answer |
|---|---|
| Product name | AEGIS AI Security Platform |
| Supplier | ZEUSTRUSTAEGISSECURITY LTD (Company № 17391549), 66 Paul Street, London EC2A 4NA |
| Contact | jdbsale3@gmail.com · 01922 445318 |
| Product description | AI-focused cybersecurity platform: 8 modules (prompt-defense, agent authorization, RAG security, supply-chain scanning, vector encryption, model-extraction defense, self-protection, advanced multimodal defenses), 37+ API endpoints, 24 layered defenses. Protects LLM/AI applications end-to-end. |
| Intended use | Securing AI/LLM deployments for NHS digital services (incl. potential NHS ID Card & digital identity programme) |
| UK-based? | Yes — UK company, UK-based development |

## B. CLINICAL SAFETY (refreshed DTAC section 1)
1. **Have you completed a Clinical Safety assessment (DCB0129)?** 
   **[PENDING]** — AEGIS is infrastructure/security software; as a class-1-style non-directly-clinical product, DCB0129 is not mandatory at this stage, but we commit to completing the DCB0129/DCB0160 safety case with the clinical team at the point of NHS deployment. *Action: confirm scope with NHS IT on Monday.*
2. **Safety case / hazard log maintained?** AEGIS runs continuous self-protection checks (config-integrity, runtime-state) and logs all security events to an immutable audit trail (tool_audit), providing hazard-log-equivalent evidence for security events. Full DCB documentation to follow pre-deployment.

## C. DATA PROTECTION (section 2) — de-duplicated with DSPT
1. **ICO registration:** Registered (ref C2015509 ZA) **[VERIFY FEE PAID]**
2. **UK GDPR / DPA 2018:** AEGIS is built GDPR/DPA-ready by design — data minimisation, encryption at rest (Fernet/AES), field-level vector encryption, PII export controls (HR PII block policy), rights-supporting audit trail.
3. **DSPT:** Self-assessment **completed** (current). DSPT evidence pack maintained and available.
4. **DPIA:** Draft DPIA in the compliance pack **[PENDING formal sign-off before deployment]**.
5. **Data residency:** UK/EU hosting (DigitalOcean EU-west-2 origin, Cloudflare edge); no offshore data processing.
6. **Sub-processors:** DigitalOcean, Cloudflare, AWS S3 (backups). Register of sub-processors maintained. GDPR-compliant DPA covering processors drafted in contract pack.

## D. TECHNICAL SECURITY (section 3) — de-duplicated with DSPT
1. **Access control / auth:** API-key authentication with 401 enforcement + RBAC admin-gated routes (keys, decrypt, policy) + rate limiting (120 req/min, headers live).
2. **Security testing:** Penetration audit completed; **8/8 findings fixed and re-verified** (hacker-2 validated).
3. **Vulnerability management:** Dependabot + CodeQL + Trivy in CI; **0 open HIGH alerts** (dependencies: torch 2.13.0, transformers 5.16.1, pytest 9.1.1 — patched).
4. **Supply chain:** AEGIS scans itself (self-scan gate — own requirements must stay fully pinned; CI-enforced).
5. **Backups & DR:** Nightly tar + Postgres dump (restore-tested) → off-site AWS S3 eu-west-2.
6. **Cyber Essentials:** **[PENDING]** — committed; booking assessment (free of DTAC requirements but strongly recommended). ISO27001 planned post-contract.
7. **Logging/monitoring:** Immutable audit trail (trigger-enforced), security events logging, prometheus metrics endpoint.

## E. INTEROPERABILITY (section 4)
1. **APIs:** OpenAPI-documented REST API (documented OpenAPI spec, docs.trading212-style endpoints); all 37+ endpoints functional; per-module health endpoints.
2. **Standards:** REST/JSON, HTTPS/TLS everywhere, webhooks-ready (Shopify sync log pattern in governance layer proves integration capability), SIEM-export ready (structured JSON events).
3. **Identity:** Supports digital identity / verification patterns (agent-auth, vector access/check, digital identity roadmap for NHS ID Card).

## F. USABILITY & ACCESSIBILITY (section 5)
1. **Accessibility:** Web dashboard is text-first with WCAG-aligned contrast/typography; **[PENDING]** formal WCAG 2.2 audit before public NHS use.
2. **Usability:** API-first with clear docs; onboarding guide existing (AEGIS-Client-Onboarding-Guide); live demo script existing.
3. **User support:** Dedicated support contact; security notice procedures; incident response plan drafted in contract pack.

## G. DEPLOYMENT & ASSURANCE CONTEXT
- **Regions:** UK/EU deployment ready; GDPR-friendly.
- **Evidence pack:** AEGIS-DTAC-DSPT-EVIDENCE-PACK + AEGIS-SECURITY-FIXES-20260829 (15 CVEs cleared, self-scan gate, key-mgmt router fixed) available for NHS IT review.
- **Monday demo:** 8-step live demo (health → auth 401 → injections blocked → benign passes → module showcase → rate headers → RBAC → backups).

## H. PRE-SUBMISSION ACTION LIST
1. ✅ Confirm ICO fee **paid** (ref C2015509 ZA)
2. ✅ Complete Cyber Essentials application (fast-track)
3. ✅ Sign off DPIA
4. ✅ Confirm DCB0129 scope with NHS IT (Monday)
5. ✅ Book WCAG 2.2 accessibility audit
6. ✅ File trademarks (separate pack) — brand protection ahead of NHS exposure

**END — All IP belongs to JDB Sales.**