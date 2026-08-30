# ZEUSTA ACCOUNTS DEPARTMENT — FULL OPERATING PLAYBOOK
**Version:** 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales · Operating for ZEUSTRUSTAEGISSECURITY LTD (Companies House 17391549, 66 Paul St, London EC2A 4NA)

---

## 1. MISSION
The Accounts Department is ZEUS AI's in-house finance function. It runs the complete financial operation of ZEUSTRUSTAEGISSECURITY LTD ("ZEUSTA"): sales ledger, purchases, cash, payroll & pensions, VAT, corporation tax, statutory filing, management accounts and weekly KPI reporting — end to end, with the human (Darren) approving every external commitment.

All IP belongs to JDB Sales; JDB Sales licenses IP to ZEUSTA (holding co).

## 2. THE LEDGER SYSTEM (company book — `ZEUS-AEGIS-COMPANY-BOOK.xlsx`, 16 sheets)
| Sheet | Purpose | Feeds from |
|---|---|---|
| 1 Dashboard | live KPIs: cash, receivables, payables, payroll, VAT, burn | all sheets |
| 2 Tracker | company milestone/actions register | manual |
| 3 Forecast | 12-month cash flow forecast | sales pipeline + history |
| 4 Quotes | issued quotations | manual + ZEUS draft |
| 5 Invoices | sales ledger — invoices issued | **Stripe webhook** `invoice.*` + manual |
| 6 Customers | customer master | **Stripe** `customer.*` webhooks |
| 7 Payments | receipts (Stripe balance) | **Stripe** `payment_intent.succeeded`, `invoice.paid` |
| 8 Suppliers | purchase ledger | manual |
| 9 Expenses | cost register | manual + ZEUS |
| 10 Payroll & Pension | RTI payroll + pension | monthly run |
| 11 Tax & VAT | VAT return prep + CT | automatic from 5/7/9 |
| 12 Trademarks | IP portfolio + renewal dates | manual |
| 13 Domains | domain register + renewal | RDAP + manual |
| 14 RFI Tracker | NHS/RFI pipeline | manual |
| 15 RFI Response Tracker | bureau responses | manual |
| 16 Compliance Tracker | ICO, CH, deadlines | calendar + manual |

**Single source of truth = the XLSX** (in repo `docs/security/` + Google Sheets export for live views). Every income event lands here via automation; nothing is ever only in chat.

## 3. AUTOMATION INTAKE (already live)
- **Stripe webhooks** → `https://apiaegissecurity.tech/stripe/webhook` (verified): `invoice.paid`, `invoice.payment_succeeded`, `payment_intent.succeeded`, `checkout.session.completed`, `invoice.payment_failed`, subscriptions lifecycle → logged to `/opt/aegis/data/stripe-events.jsonl` → **Accounts Department rhythm: weekly reconcile → write to Sheets 5/6/7**.
- **Shopify** (`orders/paid` etc.) → receiver LIVE; storefront registration pending `shpat_…` token → then order income flows the same path.
- **Idempotency guaranteed** (`processed_events` store) — no double-posting, ever.

## 4. THE ACCOUNTS RHYTHM (what "running the whole company" means weekly/monthly)
### Daily (2 min)
- Check Stripe balance + latest events (`GET /v1/balance`, webhook log tail) → flag anything unexpected (refunds, failures).

### Weekly (Monday — the "no more Friday reports by hand" brief)
1. **Income reconciliation** — Stripe invoices/orders vs webhook log vs Sheets 5/7; post anything missing (idempotency-safe).
2. **Cash position** — bank + Stripe available/pending + forecast shortfall alert (Sheet 3).
3. **Receivables** — invoices `open` overdue > 7 days → draft chase email (Darren approves).
4. **Payables** — expenses/supplier invoices due this week → payment list for approval.
5. **KPI brief** — send Monday email: revenue, income vs forecast, receivables, payables, runway, CWV/GEO stats if requested.

### Monthly close (last 3 days)
1. Reconcile every ledger sheet; balance to bank + Stripe statements.
2. **VAT return prep** (quarterly in reality; monthly prep): output tax (5/7) − input tax (8/9) → draft MTD-ready return.
3. **Payroll & pension** — run RTI payroll (Sheet 10), pension contributions, FPS to HMRC (Darren submits), net pay list.
4. **Management accounts** — P&L, balance sheet, cash flow variance vs forecast (Sheets 2/3/11) → summary for Darren.
5. Archive month: bump `processed_events` TTL, rotate webhook logs (runbook §2.4).

### Quarterly / annual statutory
- **VAT return** (if registered) via Making Tax Digital.
- **CT600 + annual accounts** — prepare from 12-month ledger; Darren files (or accountant).
- **Confirmation Statement** — Companies House (73 days after 31 Jul? — set from incorporation), keeper: Sheet 16 + google_calendar reminder.
- **ICO renewal** (ZEUSTA ICO pending C2015509) — track in Sheet 16.
- **Trademark renewals** (Sheet 12) — ZEUS/AEGIS/ZEUSTA marks, 10-year renewals.

## 5. CASH & APPROVAL RULES (HARD GATES)
| Action | Gate |
|---|---|
| Issue invoice | Darren confirms amount + customer (draft first) |
| Finalize/charge invoice | explicit go — never auto-charge |
| Pay supplier / expense | Darren approves payment list (amount + payee) |
| Payroll run | Darren confirms before FPS |
| VAT / CT filing | Darren submits (or accountant) |
| Refund | Darren approves; Stripe dashboard for money |
| Read-only (balance/status/lists) | free, no gate |

## 6. WHAT ZEUS AI (the Accounts Department employee) DOES
- Owns the monthly cycle end-to-end: books income from webhooks, updates the company book, prepares payroll/VAT/CT data, drafts the weekly KPI brief and Monday email.
- Uses connected tools: gmail (send/read), google_sheets (live book), google_drive (evidence), slack (alerts), google_calendar (deadlines), todoist (tasks).
- Every external commitment stops for Darren's approval (section 5). Nothing is invented: no fake amounts, no guessed deadlines, no unverified "done".
- Maintains the audit trail: every event in the JSONL logs, every change recorded.

## 7. FIRST 7 DAYS (ramp checklist)
1. ✅ Stripe live + verified (key in secrets, webhook receiving)
2. ✅ Webhook auth + idempotency + test suite (113 tests green)
3. ⏳ Shopify storefront webhooks (needs `shpat_…` Admin token) → then test `orders/paid`
4. Re-sync Sheets 5/6/7 with live Stripe data (products/customers/invoices)
5. Load Sheet 8/9 (suppliers/expenses) from Darren's current records
6. Confirm payroll setup + HMRC RTI details in Sheet 10
7. First weekly KPI brief → schedule Monday delivery

## 8. KEY DATES / DEADLINES (to calendar)
- NHS England meeting: **Thu 1 Oct 16:00–16:30 Teams**
- Domain renewals: zeusintelligence.com **2026-09-17** ⚠️ · zeusaiintelligence.com 2027-08-07 · apiaegissecurity.tech 2027-07-27
- ICO renewal (C2015509 pending), confirmation statement anniversary, trademark renewals — all in Sheet 16 + google_calendar

**END — All IP belongs to JDB Sales.**