# ZEUS NHS — SELF-SUFFICIENT SERVER INFRASTRUCTURE & COSTINGS
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD**
Purpose: the infrastructure ZEUSTA owns/operates AFTER winning the contract — fully self-sufficient, UK-sovereign, costed at three scales.

---

## 1. ARCHITECTURE PRINCIPLES
- **UK-sovereign hosting** — all identity/consent data in UK-based data centres (public cloud UK region or sovereign cloud); data-embassy style off-site backup (the e-Estonia lesson).
- **Own every layer** — ZEUS DOC identity, AEGIS security, ledger, registries, card personalisation control, monitoring. No critical dependency on a third-party runtime.
- **Three tiers of service** — everything runs in **pairs across two UK zones** for resilience (HA), with a DR copy off-site.
- **Bureau partner for card manufacture & post** (Certus/G+D/Thales/Entrust as RFI'd); personalisation keys controlled by ZEUS/HSM.

## 2. SERVER STACK (what we run)

### Compute clusters (bare-metal or dedicated cloud instances — sovereignty first)
| Cluster | Purpose | Sizing basis |
|---|---|---|
| **Identity cluster** — ZEUS DOC ×2 zones | tokenless identity, threshold signing, challenge/verify | 50M identities, ~1M daily challenges, crypto CPU |
| **AEGIS security cluster** | 8 modules, prompt-injection/anomaly defense, self-protection | shields all API traffic; GPU not required for v1 |
| **Ledger & registry cluster** | consent receipts (idempotent), NHS-number master data, dedupe/linkage | 50M records + audit trail, Postgres |
| **API gateway + webhooks** | external-facing API, Stripe/Shopify webhooks, NHS Spine adapter | all traffic ingress |
| **Card personalisation control** | issue/revoke/lifecycle, key ceremony control (HSM-connected) | 50M card lifecycle |
| **Monitoring & observability** | uptime, incidents, AIOps | all platforms |
| **Backup/DR** | encrypted off-site copies | full scheme DR |

### Workload sizing estimate (3 scales)
| Workload | Pilot (1 ICB ~1M) | Regional (~10 ICBs ~10M) | National 50M |
|---|---|---|---|
| Users | 1,000,000 | 10,000,000 | 50,000,000 |
| Daily auth events | ~20k | ~200k | ~1M |
| Peak TPS (auth) | ~50 | ~500 | ~2,500 |
| Concurrent sign-ins | ~2k | ~20k | ~100k |
| Storage (ledger+registry) | 0.2 TB | 2 TB | 10 TB (+audit growth) |

## 3. CONCRETE SERVER BUILD (national — the "win the contract" build)
| Node type | Spec | Qty (2 zones + DR) | Est unit/mo (£) |
|---|---|---|---|
| **Identity/crypto nodes** | 8 vCPU, 32 GB RAM, NVMe, 5 Gbps | 6 (2×zone + 2 DR) | 260 |
| **Database nodes (Postgres + ledger)** | 8 vCPU, 32 GB, 500 GB NVMe | 6 | 300 |
| **AEGIS security nodes** | 8 vCPU, 32 GB, GPU optional | 6 | 320 |
| **API gateway nodes** | 4 vCPU, 8 GB | 6 | 120 |
| **Card lifecycle/HSM nodes** | 4 vCPU, 16 GB, HSM-adjacent | 4 | 180 |
| **Observability** | 8 vCPU, 32 GB | 3 | 240 |
| **Storage (object, ledger archive)** | S3-equivalent UK | 30 TB (+retention) | 600 |
| **Managed Postgres tier** | if managed DB preferred | — | +900 |

### HSM (Hardware Security Modules) — the non-negotiable
| Item | Purpose | Est cost |
|---|---|---|
| HSM pair (PKCS#11, FIPS 140-2 L3) | CA root, card master keys, threshold key ceremony | £30k–£50k capital + £400/mo |
| Key ceremony room/process | SOP for generating + splitting master keys | process cost |

## 4. NATIONAL MONTHLY COSTING (indicative, GBP)
| Item | Pilot £/mo | Regional £/mo | National £/mo |
|---|---|---|---|
| Compute (identity/API/AEGIS) | 1,200 | 4,800 | 18,000 |
| Database + storage | 800 | 3,200 | 12,000 |
| Observability | 600 | 1,200 | 3,000 |
| HSM amortisation | 500 | 500 | 500 |
| Backups/DR | 300 | 900 | 2,400 |
| Network/egress/load balancers | 200 | 700 | 2,000 |
| **Subtotal infra** | **3,600** | **11,300** | **37,900** |
| Support/on-call (2 engineers + sre) | 6,000 | 8,000 | 14,000 |
| Licences (OS, monitoring) | 200 | 700 | 2,000 |
| **Total monthly** | **~£9,800** | **~£20,000** | **~£53,900** |
| **Annual** | **~£118k** | **~£240k** | **~£647k** |

### Why this is small vs the prize
- National infra ≈ **£0.65M/yr** vs £865M/yr contract tier (0.075% of contract value) — margins massive.
- Card + reader + personalisation costs sit in the programme's per-unit budget (cards ~£3–£5 each incl. chip/post; bureau-managed).
- 28.2x ROI business case leaves huge headroom for infra.

## 5. SELF-SUFFICIENCY CHECKLIST
- [ ] UK data residency contractually committed by host
- [ ] HSM pair + key ceremony SOP (threshold-split master keys — same doctrine as ZEUS DOC)
- [ ] AEGIS security nodes in front of every API (our own defense, not a vendor's)
- [ ] Webhook/ledger idempotency already proven; scales horizontally
- [ ] Backup: UK off-site + data-embassy DR (off-UK, encrypted) — the Estonia lesson
- [ ] On-call runbook + incident drills (we have the runbooks)
- [ ] Bill-of-materials costed at 3 scales (above) for contract negotiation

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**