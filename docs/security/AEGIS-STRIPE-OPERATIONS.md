# AEGIS / ZEUS — STRIPE OPERATIONS (LIVE)
**Version:** 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales.

---

## 1. ACCOUNT (verified live)
| Field | Value |
|---|---|
| Account ID | `acct_1TqgnLIacLYfMphY` |
| Business name | Jdbsales (JDB Sales / ZEUS AI Intelligence) |
| Country / currency | GB / GBP |
| Payouts enabled | YES |
| Charges enabled | YES |
| Balance at wiring | £0.00 available · £0.00 pending |

## 2. KEYS & SECRETS (never in code/docs/logs/chat)
| Item | Where it lives |
|---|---|
| Publishable key `pk_live_…` | Stripe dashboard (client-side only) |
| Secret key `sk_live_…` | Website secret `STRIPE_SECRET_KEY` on zeus-store (app `66f21115`, https://zeus-store.higgsfield.app) — read server-side via `bindings().STRIPE_SECRET_KEY` |
| Webhook signing secret `whsec_…` | `/etc/aegis/stripe.env` on the AEGIS droplet (mode 600), loaded via systemd drop-in `aegis-api.service.d/stripe.conf` — read as `STRIPE_WEBHOOK_SECRET` |

## 3. TEST INVOICE (draft — no charge)
- Invoice: **`in_1UA6LoIacLYfMphYoEW7EJnm`** — status **draft**, GBP 1.00 line item ("ZEUS test invoice line")
- Customer: `cus_VAREnORZjBmFCF` (darren.test@zeusaiintelligence.com)
- NOT finalized, NOT sent, NOT charged. Safe to void/delete.

## 4. WEBHOOK (LIVE — verified 30 Aug 2026)
| Field | Value |
|---|---|
| Endpoint | `https://apiaegissecurity.tech/stripe/webhook` (public, HTTPS) |
| Stripe webhook id | `we_1UA6PUIacLYfMphYF9IKY5Mg` (enabled) |
| API version | 2024-06-20 |
| Signature | HMAC-SHA256, `Stripe-Signature` header, 5-min replay window, constant-time compare (stdlib, no SDK) |
| Event log | `/opt/aegis/stripe-events.jsonl` (append-only, owned by user `aegis`) |
| Auth | `/stripe/webhook` whitelisted in the API-key middleware (Stripe can't send a key); **all other `/stripe/*`** endpoints remain key-gated |

### Enabled events (12)
`checkout.session.completed` · `invoice.paid` · `invoice.payment_succeeded` · `invoice.payment_failed` · `invoice.finalized` · `payment_intent.succeeded` · `payment_intent.payment_failed` · `customer.subscription.created` · `customer.subscription.updated` · `customer.subscription.deleted` · `customer.created` · `customer.deleted`

### Behaviour
- **Verified events → 200 immediately** (Stripe stops retrying); logged to JSONL; business action logged:
  - `invoice.payment_succeeded` / `invoice.paid` → `PAYMENT RECEIVED <cur> <amount/100>`
  - `checkout.session.completed` → `CHECKOUT COMPLETED … email`
  - `payment_intent.succeeded` → `PAYMENT INTENT SUCCEEDED`
  - `customer.subscription.*` → `SUBSCRIPTION CREATED/UPDATED/DELETED`
  - `invoice.payment_failed` → `PAYMENT FAILED` (warning)
- **Bad signature → 400** · **Unconfigured secret → 500** · unknown events → 200 + logged (ignored)

### Internal endpoints (key-gated)
- `GET /stripe/webhook/status` — configured? recent 5 events
- `GET /stripe/webhook/events?limit=N` — last N received events

## 5. E2E TEST RECORD (30 Aug 2026)
1. `evt_test_zeus_e2e_001` (invoice.payment_succeeded, gbp 5000.0) → HTTP 200, action fired `PAYMENT RECEIVED gbp 5000.0` — found + fixed log permission bug
2. `evt_test_zeus_e2e_002` (invoice.payment_succeeded, gbp 30000.0) → HTTP 200, full event record appended to JSONL ✅
3. Unsigned POST → HTTP 400 ✅ · no-key GET /status → HTTP 401 ✅

## 6. LIVE PRODUCTS / PRICES (existing)
| Product | id |
|---|---|
| aegis security platform | `prod_UzHRt3HB4b0rQk` |
| aegis security platform pro | `prod_UzHmhz5aCuj1tA` |
| aegis security enterprise | `prod_UzHrjeSS822kmc` |
| ZEUS Marketplace Pro | `prod_V7Dhs1LudNWiiY`, `prod_V7DhpP64TmpU29` |
| ForgeFit Pro/Monthly/Yearly | `prod_UwbkDC3wR9w8x6` etc. |

Payment links: Starter £5,000/yr · Professional £30,000/yr · Enterprise £100,000/yr (buy.stripe.com — see STRIPE-WEBHOOK-SETUP.md).

## 7. AUTOMATION HOOKS (from zeus-stripe-operations skill)
- Payment received → send receipt (invoice_pdf) via Gmail
- Invoice processor → company book sheet 8
- Weekly revenue → Monday KPI brief (`GET /v1/balance`)
- Subscription lifecycle changes → Slack/email notify

## 8. SAFETY RULES (locked in ZEUS)
- Read-only (balance/status/lists) run freely.
- Anything that charges, finalizes, refunds or creates customers/invoices on the live account **requires explicit Darren confirmation** (amount + currency + recipient shown) before POST.
- Never log or store the keys; never paste them into chat.

**END — All IP belongs to JDB Sales.**