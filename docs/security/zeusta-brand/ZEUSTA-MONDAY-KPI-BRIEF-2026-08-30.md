# MONDAY KPI BRIEF — ZEUSTA
**Week of 30 Aug 2026 · Prepared by the ZEUS Accounts Department · All IP belongs to JDB Sales**

---

## 1. CASH POSITION (live, verified)
| Metric | Value |
|---|---|
| Stripe available | **£0.00** |
| Stripe pending | **£0.00** |
| Verified sources | Stripe API balance (read-only, live) |

**Note:** revenue is pre-launch. The 5 digital products are staged for the storefront; first income expected from store go-live.

## 2. INCOME PIPELINE (live webhook evidence)
| Rail | Status | Events (lifetime) | Last activity |
|---|---|---|---|
| Shopify store webhooks | **LIVE 10/10 topics** | 37 verified deliveries | 30 Aug (test notifications + real order 1234 £404.95 event) |
| Stripe webhooks | **LIVE** | 2 events logged (test invoice lifecycle) | 30 Aug |
| Receipt ledger (Sheets) | **LIVE** | 1 receipt posted (order 1234) | 30 Aug |

- 10 Shopify topics covered: orders/create · paid · fulfilled · cancelled · refunds/create · products/create · update · customers/create · update · themes/publish
- Test invoice to watch: `in_1UA6LoIacLYfMphYoEW7EJnm` (draft→open, £1.00, number YTYJT4JO-0002, **not** paid — non-income)

## 3. RECEIVABLES & PAYABLES
| Item | Amount | Status |
|---|---|---|
| Receivables (open invoices) | £1.00 (test invoice) | open — void or collect per decision |
| Payables | £0.00 | no open supplier invoices |
| Subscriptions (Stripe) | 0 active | none yet |

## 4. OPERATIONAL HEALTH
| Check | Status |
|---|---|
| Webhook idempotency test suite | **113/113 tests green** |
| Stripe + Shopify receivers | configured TRUE, HMAC-verified |
| Event-log continuity | Stripe 2 · Shopify 37 — growing, no gaps |
| Accounts Department employee | running, playbook + ledgers in context |
| Deferred: 3 app-level Shopify topics | blocked on app install (browser) — zero income impact |

## 5. THIS WEEK'S PRIORITIES (for Darren)
1. **Launch the store:** apply `SHOPIFY-SHOP-DESIGN-SPEC.md` (Dawn theme, ZEUSTA palette/logo), import `zeusta-shopify-products.csv` (5 digital products live for sale)
2. **Take first order** → watch it land in `/opt/aegis/data/shopify-events.jsonl` + Sheets (already wired)
3. **Install zeus-ai-digital-app-1** in admin (2 min) → unlocks 3 deferred topics (optional)
4. **Domain watch:** zeusintelligence.com renews **2026-09-17** ⚠️ (18 days)
5. **NHS meeting** Thu 1 Oct 16:00 Teams — deck ready

## 6. PREDICTED NEXT BRIEF (if store launches this week)
- Income: first £49–£99 digital-product orders (order/paid events)
- Receipts: auto-posted to Sheets · PAYMENT RECEIVED actions logged once (idempotent)

**END — All IP belongs to JDB Sales.**