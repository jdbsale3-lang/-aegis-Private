# AEGIS WEBHOOK RUNBOOK — Outage, Monitoring & Idempotency
**Version:** 1.1 · 30 Aug 2026 · All IP belongs to JDB Sales.

Covers the AEGIS webhook receivers at `https://apiaegissecurity.tech/stripe/webhook` (STRIPE — **live**) and `https://apiaegissecurity.tech/shopify/webhook` (SHOPIFY — **live**: receiver wired + idempotency verified 30 Aug 2026; storefront subscription registration needs the Shopify store domain).

---

## 1. RUNBOOK — WEBHOOK OUTAGE

**Worst case:** money events (invoice.paid, payment_intent.succeeded, checkout.session.completed) arrive late or not at all. The Stripe dashboard marks events `failed` after ~3 days of retries; **money already moved even if we never saw the event** — reconciliation, not panic.

### 1.1 Detection (how you'll know)
| Signal | Where |
|---|---|
| `/stripe/webhook/health` flips to `"status":"unconfigured"` or `event_log_size` stops growing | Uptime monitor / manual curl |
| Event log has old timestamps (older than the last expected payment) | `tail /opt/aegis/stripe-events.jsonl` on the droplet |
| Stripe dashboard shows `scheduled`/`failed` deliveries | Dashboard → Developers → Webhooks → endpoint → Events |
| Customer says "I paid but nothing happened" | — |
| CRON/daily check flags no events in 24h | future: add scheduled check |

### 1.2 Triage checklist (5 min)
1. **Is the server up?** `curl -s https://apiaegissecurity.tech/health` → expect 200. If down: `ssh root@178.62.46.133` → `systemctl status aegis-api.service`.
2. **Is the webhook configured?** `curl -s https://apiaegissecurity.tech/stripe/webhook/health` → `"configured": true`. If `false`: `/etc/aegis/stripe.env` missing/corrupt → restore → `systemctl restart aegis-api.service`.
3. **Was the signature rejected?** `journalctl -u aegis-api.service --since "24 hours ago" | grep -i "signature"` — if `verification FAILED` bombs, the `STRIPE_WEBHOOK_SECRET` changed (rotated in dashboard?) — update `/etc/aegis/stripe.env` and restart.
4. **Is the log writable?** `ls -la /opt/aegis/stripe-events.jsonl` — must be owned `aegis:aegis`. If `Permission denied` in logs: `chown aegis:aegis /opt/aegis/stripe-events.jsonl`.
5. **Is nginx routing?** `curl -s -o /dev/null -w "%{http_code}" https://apiaegissecurity.tech/stripe/webhook/health`.

### 1.3 Fix the common causes
| Cause | Fix |
|---|---|
| Service crashed | `systemctl restart aegis-api.service` (check `journalctl -u aegis-api.service -e` for python traceback first) |
| Secret rotated in Stripe dashboard | Copy new `whsec_…` → `/etc/aegis/stripe.env` → restart |
| Log perms | `chown aegis:aegis /opt/aegis/stripe-events.jsonl` |
| Disk full (event log exploded) | `du -h /opt/aegis/stripe-events.jsonl`; rotate (see 3.4) |
| Deadline/firewall | Stripe IPs: `137.184.108.53`, `137.184.103.53` (check docs); ensure droplet firewall allows inbound 443 |

### 1.4 Recover missed events (redelivery)
1. **Stripe Dashboard → Developers → Webhooks → endpoint → Events** → filter by status `failed` → **⋮ → Redeliver** each failed event.
2. **API alternative (scriptable — ZEUS can run it):**
   ```
   curl -u $STRIPE_KEY: -X POST https://api.stripe.com/v1/events/{event_id}/retry
   ```
   For a whole gap: list invoices `GET /v1/invoices?limit=100&status=paid` → for each `in_…` not present in the JSONL log, redeliver its `invoice.paid` event (find the event id via `GET /v1/events?type=invoice.paid&created[gte]=…&limit=100`).
3. **Verify catch-up:** `GET /stripe/webhook/events` (key-gated) — all gap events present with `ts` after recovery time.

### 1.5 Communication
- If a customer is affected, confirm payment status on Stripe dashboard FIRST (`Payment Intents` shows the money), never guess.
- Log the incident in the company book / JDB Sales record: time, cause, events recovered, money impact (£0 if all reconciled).

---

## 2. WEBHOOK MONITORING

### 2.1 Health endpoints
| Endpoint | Auth | Meaning |
|---|---|---|
| `GET /health` | none | API alive |
| `GET /stripe/webhook/health` | none | webhook configured + event log growing; **PII-free** |

### 2.2 What to monitor (a 4-metric dashboard)
1. **Endpoint up** — external monitor (UptimeRobot/Uptime Kuma) hitting `/stripe/webhook/health` every 60s; alert if non-200 or `configured != true`.
2. **Freshness** — `event_log_size` / last event `ts`; alert if no new event in 48h **when money is expected** (billing days, campaign launch, checkout test).
3. **Deliveries** — Stripe dashboard webhook Events tab: count `failed` over 24h; alert at > 0 after a redelivery pass.
4. **Service health** — `systemctl is-active aegis-api.service` + disk usage on the droplet (event log growth).

### 2.3 Scheduled checks to add (ZEUS automations)
- **Daily 08:00 (Mon–Fri):** `GET /stripe/webhook/health` + last event `ts` → if stale > 24h, notify Slack/email.
- **Weekly Monday:** reconciliation — invoices paid this week vs events in log; report to KPI brief.
- **On-demand command:** "run webhook outage check" → ZEUS runs section 1.2 triage and reports.

### 2.4 Log rotation
`/opt/aegis/stripe-events.jsonl` grows ~1 line/event. Low volume now (£0 income) but for 10k events/day ≈ 10 MB/day:
```
# daily rotation, keep 30 days
0 0 * * * cp /opt/aegis/stripe-events.jsonl /opt/aegis/stripe-events.$(date +\%F).jsonl && truncate -s 0 /opt/aegis/stripe-events.jsonl && find /opt/aegis/stripe-events.*.jsonl -mtime +30 -delete
```
(Keep ownership `aegis:aegis` on the fresh file.)

---

## 3. IDEMPOTENCY IMPLEMENTATION GUIDE

Webhooks are **at-least-once**: Stripe retries failures for 3 days, and manual redelivery resends the same `event.id`. The handler MUST be idempotent so a second delivery of the same event doesn't double-charge, double-log, or double-email.

### 3.1 Current state
- The receiver appends every delivery to the JSONL log — identical `event.id` may appear multiple times (this is allowed for auditing but must NOT drive side effects twice).
- No side effects are yet wired (log-only) — the risk is **future** automations (receipt email, company-book row, Slack alert).

### 3.2 Rule: dedupe by `event.id` before any side effect
```
if event_id in PROCESSED_IDS:   # single-instance, or DB/Redis/durable KV
    return 200                  # already handled — do nothing
mark PROCESSED               # atomic claim BEFORE the effect
... do side effect ...
```
- **Key = `event.id`** (globally unique, stable across retries and redeliveries).
- **Claim must happen BEFORE the side effect** and must be durable (survive crash).
- If the side effect itself fails after the claim: you MUST have a retry path that re-runs the effect but not a second claim (or store partial state).

### 3.3 Storage options (choose by scale)
| Scale | Store | Notes |
|---|---|---|
| ≤ 10³ events/day | JSONL file of processed ids (`/opt/aegis/processed-ids.jsonl`) | simple; compact with a nightly dedupe/trim |
| 10³–10⁵/day | SQLite table `processed_events(event_id TEXT PRIMARY KEY, ts)` | `INSERT OR IGNORE` = atomic claim |
| production / multi-instance | Postgres on the droplet (already running), table `processed_events` with `ON CONFLICT DO NOTHING`, or Redis `SETNX` with TTL (events expire for redelivery after 3 days — TTL ~7 days is safe) | immutable |

**Recommended now:** SQLite/Postgres `INSERT OR IGNORE` — single INSERT per event, atomic, no new infra:
```sql
CREATE TABLE IF NOT EXISTS processed_events (
    event_id TEXT PRIMARY KEY,
    kind TEXT,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- claiming a delivery:
INSERT INTO processed_events (event_id, kind) VALUES ('evt_x', 'invoice.paid')
ON CONFLICT (event_id) DO NOTHING
RETURNING event_id;
-- empty result ⇒ already processed ⇒ return 200 without side effects
```

### 3.4 What the handler should do (final shape)
```python
@router.post("/webhook")
async def stripe_webhook(request: Request):
    # 1. verify signature (HMAC, 5-min window) → 400 on fail  → ALWAYS, even for dupes
    # 2. parse event
    # 3. claim: INSERT OR IGNORE processed_events(event_id)
    #    - if NOT claimed (duplicate) → log "duplicate, skipped" → return 200
    # 4. if claimed and side effects enabled → run receipt/company-book/Slack actions
    # 5. always log the delivery to stripe-events.jsonl (audit trail even for dupes)
    # 6. return 200
```

### 3.5 Test the idempotency (proof it works)
1. Deliver a signed event (use the E2E recipe from AEGIS-STRIPE-OPERATIONS.md §4c).
2. **Immediately redeliver the same event.id** (resend the same payload with a fresh signature — Stripe's real retries do exactly this).
3. Assert: `processed_events` has exactly 1 row for that id, and the side effect ran once (e.g. one email, one company-book row).
4. Regression: `test_webhook_idempotent()` — two deliveries, one side effect.

### 3.6 Checklist before enabling any side-effect automation
- [ ] `processed_events` table exists and is backed up with the droplet DB
- [ ] Effect wrapped so a crash between claim and effect doesn't lose the event (use a `delivery_status` column: `claimed` → `succeeded`/`failed_retryable`)
- [ ] Duplicate deliveries return 200 (never 4xx — that would make Stripe keep retrying)
- [ ] Idempotency test in CI (see 3.5)
- [ ] Documented in this runbook (this section)

---

## 4. SHOPIFY-SPECIFIC RUNBOOK

### 4.1 Receiver (live)
- Endpoint: `https://apiaegissecurity.tech/shopify/webhook` (public, HTTPS)
- Signature: **HMAC-SHA256, Base64-encoded** in `X-Shopify-Hmac-Sha256` header — key = Shopify app **Client Secret** (`/etc/aegis/shopify.env` → `SHOPIFY_CLIENT_SECRET`, env only, never in code/logs/docs)
- Headers used: `X-Shopify-Topic`, `X-Shopify-Shop-Domain`, `X-Shopify-Webhook-Id`, `X-Shopify-Api-Version`
- Event log: `/opt/aegis/data/shopify-events.jsonl` (writable dir owned `aegis:aegis`)
- Auth: `/shopify/webhook` + `/shopify/webhook/health` public; `/shopify/webhook/status` + `/events` key-gated (same pattern as Stripe)

### 4.2 Topics wired
`orders/create` · `orders/paid` · `orders/fulfilled` · `orders/cancelled` · `refunds/create` · `products/create` · `products/update` · `customers/create` · `customers/update` · `app/uninstalled` · `app/scopes_update` · `checkouts/paid` · `themes/publish`
(All others: logged, 200-acknowledged, ignored.)

### 4.3 Delivery & retry behavior (Shopify-side)
- Shopify POSTs each webhook to the subscription address; must respond **2xx within ~5 seconds** (we return `ok` immediately after verify+claim).
- Failed deliveries: Shopify retries **up to 19 times over 48 hours** with exponential backoff. After that the delivery is dropped from the queue (no permanent dashboard "failed" stash like Stripe — check the **webhook's Recent deliveries** page in Shopify admin).
- Each attempt is a fresh POST; the HMAC is recomputed per attempt with the same Client Secret — our verification passes on every retry.
- **Idempotency is mandatory:** the same `X-Shopify-Webhook-Id` arrives on every attempt. Our shared `processed_events` store claims by webhook id — first attempt acts, the rest are acknowledged and skipped (proven: order 1005 → exactly 1 action, 1 claim, 3 deliveries, 2 skipped).

### 4.4 Failure modes — this endpoint
| Mode | Response | Shopify reaction | Fix |
|---|---|---|---|
| HMAC mismatch / missing header | 400 | retries (19x/48h) | check `SHOPIFY_CLIENT_SECRET` matches the app in the Partner Dashboard |
| Secret unset | 500 | retries | fix `/etc/aegis/shopify.env` → restart service |
| Server down | no response | retries | health probe `/shopify/webhook/health`, restart service |
| Log/DB unwritable | 200 (swallowed) | accepted | check `/opt/aegis/data` ownership (aegis:aegis) |

### 4.5 Registering storefront webhook subscriptions (NOT yet done)
The receiver is live, but Shopify must be told to POST to it. Requires the **store domain** (e.g. `store.myshopify.com`) — provide it to ZEUS and it registers via Admin API:
```
POST /admin/api/2024-10/webhooks.json
headers: X-Shopify-Access-Token: <SHOPIFY_ACCESS_TOKEN>
{"webhook": {"topic": "orders/paid", "address": "https://apiaegissecurity.tech/shopify/webhook", "format": "json"}}
```
(Or manually: Shopify Admin → Settings → Notifications → Webhooks → Add webhook.) Repeat per topic from 4.2. Access token is stored at `/etc/aegis/shopify.env` → `SHOPIFY_ACCESS_TOKEN`.

### 4.6 Redelivery / testing
- **Manual resend:** Shopify Admin → Settings → Notifications → Webhooks → the webhook → **Recent deliveries** → kebab menu → **Resend**.
- **Sandbox test:** the E2E signed-delivery recipe (compute Base64 HMAC, POST with headers) — used to verify this receiver; 3× same-id delivery asserted 1 action / 2 suppressed.
- Use `orders/paid` as the canary topic — like `invoice.payment_succeeded` on Stripe, it's the "money moved" signal and the one that feeds the receipt/accounting automations.

## 5. IDEMPOTENCY TEST SUITE
Run from `backend/`:
```
venv/bin/python -m pytest tests/test_webhook_idempotency.py -v
```
- 12 tests: atomic claim semantics · Stripe first-delivery/duplicate/bad-signature/replay-window/different-events · Shopify first-delivery/duplicate/bad-HMAC/derived-id dedupe · PII-free health endpoints
- Works against the real router code with isolated tmp env (DB + logs) — no network needed
- **Regression gate:** any change to the webhook receivers must keep this suite green (it already caught the root-owned-DB bug and the base64-vs-hex HMAC bug in the initial wiring)

**END — All IP belongs to JDB Sales.**