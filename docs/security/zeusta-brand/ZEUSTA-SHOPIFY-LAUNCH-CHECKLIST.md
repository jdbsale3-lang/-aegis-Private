# ZEUSTA SHOPIFY STORE — LAUNCH CHECKLIST
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales**

Complete, ordered launch plan. Every box is actionable from the linked assets. Items marked **(browser)** are Shopify-admin clicks only Darren can perform; **(ZEUS)** I execute on request.

---

## PHASE 1 — PRE-LAUNCH (do this first)

### Store identity
- [ ] **(browser)** Settings → Store details → store name = **ZEUSTRUSTAEGISSECURITY LTD**
- [ ] **(browser)** Fix current title typo (“zeusaiintellgence”)
- [ ] **(browser)** Set contact email jdbsale3@gmail.com · phone 01922 445318

### Theme & brand
- [ ] **(browser)** Online Store → Themes → activate **Dawn**
- [ ] **(browser)** Theme → ⋮ → Edit code → `settings_data.json` → paste **`zeusta-dawn-settings.json`** contents → Save
- [ ] **(browser)** Upload **logo** + **favicon** (zeusta-logo-master.png / zeusta-social-square.png)
- [ ] **(browser)** Add announcement bar: `★ DIGITAL DELIVERY — INSTANT · AI-GUARDED BY AEGIS · SECURE CHECKOUT VIA STRIPE`
- [ ] **(browser)** Build homepage sections to match `zeusta-store-preview.html` (hero, trust band, featured, how-it-works, FAQ, footer)

### Products
- [ ] **(browser)** Products → Import → **`zeusta-shopify-products.csv`**
- [ ] **(browser)** Verify 5 products published with images + prices (Business OS £49 · AEGIS £99 · Voice £29 · NHS £79 · Brand £39)
- [ ] **(browser)** Configure each as **digital** (no shipping) + enable Digital Downloads app or manual email fulfilment

### Payments
- [ ] **(browser)** Settings → Payments → enable Shopify Payments or connect Stripe (existing live account: acct_1TqgnLIacLYfMphY)
- [ ] **(browser)** Test checkout with test card `4242 4242 4242 4242`

## PHASE 2 — GO-LIVE (launch day)

- [ ] **(browser)** Online Store → Themes → **Publish** (make Dawn the live theme)
- [ ] **(browser)** Products → bulk edit → status → **Active** (if not already)
- [ ] **(ZEUS)** After first product goes active → run webhook sanity: `GET /stripe/webhook/health` + `GET /shopify/webhook/health` → configured true
- [ ] **(ZEUS)** Confirm test order in webhook log: `/opt/aegis/data/shopify-events.jsonl` shows `orders/paid`
- [ ] **(ZEUS)** Confirm receipt posted to **ZEUSTA-Shopify-Receipts** sheet (order row + PAYMENT RECEIVED)
- [ ] **(browser)** Announce launch on X (@jdbsales3) / LinkedIn / TikTok / IG — copy in the Brand & Marketing Pack

## PHASE 3 — POST-LAUNCH (first 7 days)

- [ ] **(ZEUS)** Monday KPI brief — first edition from live ledgers (Stripe + Shopify + Sheets)
- [ ] **(ZEUS)** Daily check: Stripe balance + webhook event counts; flag anomalies
- [ ] **(browser)** Respond to first customer questions (FAQ covers delivery/licence/refunds)
- [ ] **(browser)** Verify STRIPE payouts land (JDB Sales bank account; payouts_enabled = true)
- [ ] **(ZEUS)** Optional: 3 deferred webhooks once `shpat_…` token exists (install app → paste token → `register-shopify-app-topics.sh`)

## PHASE 4 — POST-LAUNCH (30-day)

- [ ] **(browser)** Review analytics: Online Store → Analytics (sessions, conversion, top products)
- [ ] **(browser)** Collect and add customer reviews to product pages
- [ ] **(ZEUS)** Monthly close: reconcile Sheets, VAT prep, management accounts, Monday KPIs
- [ ] **(browser)** Consider Second Collection / bundles (e.g. “Full ZEUSTA Set £259”) using same import format

---

## DEPLOY BLOCKER NOTE (honest)
Deploying the theme + products to the **live** store requires Shopify Admin access (browser). ZEUS cannot click these. The single token barrier (`shpat_…`) exists only after **app install**; all previews, JSON and CSVs are ready and verified — the deploy itself is Phase-2 browser work above.

## ASSET INDEX (all verified)
| Asset | Link |
|---|---|
| Desktop store preview | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/ef86511f-aa20-4d7b-81e9-cca7b21b29d0.html |
| Mobile store preview | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/a22eb1ee-74a1-487f-ac3b-e9cba1d1cf2c.html |
| Desktop collection | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/b09c9f8d-52d7-4547-afb1-4d83b205ef55.html |
| Collection (responsive) | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/a84167c1-83b6-43d9-97f4-57400f9f93d2.html |
| Dawn settings JSON | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/d770f9a3-a6b9-4fc3-978a-ae4abe0114e6.json |
| Products CSV | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/260bbc8a-fafd-445b-9ee5-46bd0fc71fc0.csv |
| Logo (PNG) | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/e6d7dcb8-1aa6-4912-8ebe-0ed0cac59275.png |
| Social square | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/9dc3cfb7-0c17-4df7-8af7-a864448d2b11.png |
| Full setup guide | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/1fdc419b-139b-4788-bb86-a50b71e7b912.md |

**END — All IP belongs to JDB Sales.**