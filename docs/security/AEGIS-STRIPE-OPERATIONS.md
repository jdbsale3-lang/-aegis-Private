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

### Auth whitelist map (THE COMPLETE RULE — production)
| Path | Public (no key) | Why |
|---|---|---|
| `/health` | ✅ | uptime |
| `/api/v1/register` (+ prefix) | ✅ | on-boarding |
| `/terms` | ✅ | legal |
| `/stripe/webhook` (POST) | ✅ | Stripe delivery — signature verified inside handler (HMAC, 5-min window) |
| `/stripe/webhook/health` (GET) | ✅ | PII-free uptime probe for monitors |
| `/stripe/webhook/status` (GET) | 🔒 401 | reveals config — key-gated |
| `/stripe/webhook/events` (GET) | 🔒 401 | reveals event data (may include emails) — key-gated |
| everything else | 🔒 401 | standard API-key gate + RBAC + quota |

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
- `GET /stripe/webhook/health` — PUBLIC: `{status, service, configured, event_log_size}` — no PII

## 4b. INVOICE LIFECYCLE (tested end-to-end 30 Aug 2026)
Full recipe (verified live):
1. **Create customer** → `POST /v1/customers` → `cus_…`
2. **Add line item** → `POST /v1/invoiceitems` `customer=…&amount=…&currency=gbp&description=…`
3. **Draft invoice** → `POST /v1/invoices` `customer=…&auto_advance=false` → `in_…` (status `draft`). Note: line items attach to the NEXT invoice created after them — if draft already exists, pass `invoice=in_…` on the invoiceitems call.
4. **Finalize** → `POST /v1/invoices/{id}/finalize` → status `open`, `number` assigned, `hosted_invoice_url` + `invoice_pdf` generated. No charge yet.
5. **Customer pays** (hosted page) → `invoice.payment_succeeded` + `invoice.paid` webhooks → AEGIS logs `PAYMENT RECEIVED` → automation hooks.
6. **Void** → `POST /v1/invoices/{id}/void` (uncollectable/test cleanup).

## 4c. E2E TEST RECORD — REAL DELIVERY (30 Aug 2026)
Earlier synthetic signed tests (evt_test_zeus_e2e_001/002) proved verification + action. Then the real world:
- Finalized `in_1UA6LoIacLYfMphYoEW7EJnm` (GBP 1.00) → status `open`, invoice number **YTYJT4JO-0002**
- Stripe delivered **(from Stripe's own IP 54.187.174.169)** → `evt_1UA6kFIacLYfMphYNi9FKHHw` `invoice.finalized` → **HTTP 200**, logged to JSONL ✅
- `hosted_invoice_url` → **HTTP 200** (live payment page) · `invoice_pdf` → 302 (file)
- Unsigned POST → 400 ✅ · no-key `/status` → 401 ✅ · no-key `/health` → 200 ✅
- **E2E verdict: real Stripe → AEGIS delivery confirmed with zero synthetic payloads.**

## 5. WEBHOOK RETRY BEHAVIOR, FAILURE MODES & MANUAL REDELIVERY

### 5.1 Retry behavior (Stripe-side, documented)
- Stripe considers a delivery **successful** only when the endpoint responds **2xx**.
- Any **non-2xx** (400/401/500/…), **timeout**, or **network/TLS error** → Stripe automatically retries with **exponential backoff over ~3 days** (early retries come within minutes, later ones spaced hours apart).
- While retrying, the event row in the Stripe dashboard shows status **`scheduled`** with one delivery attempt per retry; each attempt is a fresh POST from Stripe's servers with a **newly generated `Stripe-Signature`** (new `t=` timestamp), so our 5-minute replay window applies per attempt and never rejects a legitimate retry.
- After the ~3-day window without a 2xx, Stripe **stops retrying** and marks the event **`failed`**. It will **not** come back automatically — manual redelivery is required (5.3).

### 5.2 Failure modes — this endpoint, mapped
| Mode | Response we return | Stripe's reaction | How to detect / fix |
|---|---|---|---|
| Signature verification fails (bad secret, tampered, replay) | **400** `invalid signature` | retries (up to 3 days) | check `stripe-signature` header + `STRIPE_WEBHOOK_SECRET`; `/stripe/webhook/health` |
| Webhook secret not set (systemd env missing) | **500** `webhook not configured` | retries | fix `/etc/aegis/stripe.env` → `systemctl restart aegis-api.service` |
| Malformed JSON body | **400** `invalid JSON` | retries | see raw body in Stripe event deliveries panel |
| Event log write failure | **200** (logging error swallowed — never blocks the response) | accepted, no retry | check `/opt/aegis/stripe-events.jsonl` perms (owned `aegis:aegis`) |
| Unknown/unhandled event type | **200** `ok`, logged-only | accepted, no retry | expected — event types are additive |
| Server down / nginx timeout / TLS issue | no response | retries | `/stripe/webhook/health` from a monitor; uptime check on `apiaegissecurity.tech` |
| **Idempotency** | n/a | n/a | every delivered event (incl. retries + redeliveries) is appended once per delivery to the JSONL log — **the same `event.id` can appear multiple times**. Log-only actions are fine; any future side-effect automation (send receipt, update sheet) MUST dedupe by `event.id` before acting. |

### 5.3 Manual redelivery (Stripe Dashboard)
When an event shows **`failed`** (or you just want it re-sent):
1. Open **Dashboard → Developers → Webhooks** → click our endpoint (`https://apiaegissecurity.tech/stripe/webhook`).
2. Go to the **Events** tab (lists event deliveries, status `delivered` / `scheduled` / `failed`, with response code + body per attempt).
3. Find the event and click its **⋮ (kebab) menu → Redeliver**. Stripe re-sends it to the endpoint with a fresh signature; it lands in `/opt/aegis/stripe-events.jsonl` as a new delivery of the same `event.id`.
4. Confirm: `GET /stripe/webhook/events` (key-gated) or tail the JSONL on the droplet.
- **API alternative:** `POST /v1/events/{event_id}/retry` with the secret key (same effect, scriptable — ZEUS can do this on request).

### 5.4 Operational notes
- **Gap detection:** compare invoices/subscriptions we know exist (e.g. via `GET /v1/invoices`) against `event.id`s in the JSONL log — anything missing after an outage gets redelivered via 5.3.
- **Ordering is not guaranteed:** Stripe delivers events as they happen and retries can arrive out of order. Never assume chronological order — use the event/object `created` timestamps when sequencing matters (e.g. `invoice.paid` before `invoice.payment_succeeded` is possible).
- **Health probe for monitors:** `GET /stripe/webhook/health` (public, PII-free) → `{"status":"ok","configured":true,"event_log_size":…}` — wire this into any uptime watcher to catch the "server down" failure mode early.

> **For the full playbook:** outage response (section 1), monitoring (section 2), and the idempotency implementation guide with `processed_events` SQL (section 3) live in **`AEGIS-WEBHOOK-RUNBOOK.md`** — same folder.

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