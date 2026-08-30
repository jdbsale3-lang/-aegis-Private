# ZEUSTA SHOPIFY STORE — COMPLETE SETUP GUIDE
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales**

This guide takes the ZEUSTA store from blank Dawn theme to a live, branded, revenue-ready shopfront in ~20 minutes. Every asset referenced here already exists in the repo (`docs/security/zeusta-brand/`) and is verified.

---

## STEP 1 — STORE IDENTITY (2 min)
1. Admin → **Settings → Store details**
2. Store name: **ZEUSTRUSTAEGISSECURITY LTD**
3. Fix any typos (the current store title has one: "zeusaiintellgence")
4. **Save**

## STEP 2 — THEME (8 min)
1. **Online Store → Themes** → use **Dawn** (free) → **Customize**
2. **Colors** (Theme settings → Colors) → paste the three schemes from `zeusta-dawn-settings.json`:
   - Base background `#10131B` · cards `#1B2030` · text `#FFFFFF` · buttons `#4FCEE4` · button label `#10131B` · badge `#D9F24B`
3. **Typography:** Inter (headings bold, body regular) — file has the exact tokens
4. **Logo & favicon**: Online Store → Themes → **⋮ → Edit code** → open `settings_data.json` → replace the `"current": { … }` block with the contents of `zeusta-dawn-settings.json` → **Save** → the entire identity applies at once
5. Set **logo image** + **favicon** to `zeusta-logo-master.png` / `zeusta-social-square.png` (already uploaded to CDN, links below)
6. **Announcement bar:** `★ DIGITAL DELIVERY — INSTANT · AI-GUARDED BY AEGIS · SECURE CHECKOUT VIA STRIPE`

## STEP 3 — PRODUCTS (5 min)
1. Admin → **Products → Import** → upload **`zeusta-shopify-products.csv`**
2. Verify all 5 appear with covers, prices, SEO:
   | Product | Price | Compare-at |
   |---|---|---|
   | ZEUS Business OS Toolkit | £49.00 | £69.00 |
   | AEGIS AI Security Starter Assessment | £99.00 | £129.00 |
   | ZEUS Voice Assistant Starter Kit | £29.00 | £39.00 |
   | NHS-Tech Supplier Playbook | £79.00 | £99.00 |
   | ZEUSTA Brand & Marketing Pack | £39.00 | £49.00 |
3. Each product: **digital download** → no shipping required → enable the **Digital Downloads** app (free) or manual email fulfilment
4. Currency **GBP** (already set)

## STEP 4 — HOMEPAGE SECTIONS (5 min)
Build in order (match `zeusta-store-preview.html`):
1. Announcement bar (above)
2. **Hero:** "The AI-Guarded Digital Economy" + cyan CTA **Shop the collection**
3. **Trust band:** Instant delivery · Stripe secured · AEGIS-protected · Built by JDB Sales / ZEUSTA
4. **Featured collection:** the 5 products (auto from product tags `digital-download`)
5. **Benefits** (Why ZEUSTA) + **How it works** (4 steps) + **FAQ** (delivery/licence/refunds)
6. **Footer:** logo + "All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD · CH 17391549"

## STEP 5 — CHECKOUT & PAYMENTS (2 min)
1. **Payments:** Shopify Payments OR enable the existing Stripe connection
2. Test with Stripe test card `4242 4242 4242 4242` (or a £1 test product)
3. First real order → webhook fires → receipt posts to **ZEUSTA-Shopify-Receipts** sheet automatically

## STEP 6 — OPTIONAL: INSTALL THE APP + 3 DEFERRED WEBHOOKS
1. Settings → **Apps and sales channels** → install **zeus-ai-digital-app-1** → approve scopes
2. Copy **Admin API access token** (`shpat_…`) → send to ZEUS
3. ZEUS runs `register-shopify-app-topics.sh` → registers `app/uninstalled`, `app/scopes_update`, `checkouts/paid` → reads back 13/13

---

## ASSET INDEX (verified links)
| Asset | Link |
|---|---|
| Desktop store preview | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/ef86511f-aa20-4d7b-81e9-cca7b21b29d0.html |
| Mobile store preview | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/a22eb1ee-74a1-487f-ac3b-e9cba1d1cf2c.html |
| Collection page preview | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/a84167c1-83b6-43d9-97f4-57400f9f93d2.html |
| Dawn theme settings JSON | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/d770f9a3-a6b9-4fc3-978a-ae4abe0114e6.json |
| Products import CSV | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/260bbc8a-fafd-445b-9ee5-46bd0fc71fc0.csv |
| Master logo (PNG) | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/e6d7dcb8-1aa6-4912-8ebe-0ed0cac59275.png |
| Social square / avatar | https://d2ol7oe51mr4n9.cloudfront.net/user_3GJd975B4Ec780O9XOwnwdY7BEs/9dc3cfb7-0c17-4df7-8af7-a864448d2b11.png |
| Product pages (5) | folder links in chat · `product-pages/*.html` |
| Mobile product pages (5) | `mobile-product-pages/*-mobile.html` |

## GO-LIVE CHECKLIST
- [ ] Store name fixed (ZEUSTA …)
- [ ] Dawn theme + settings JSON applied (dark, cyan/acid)
- [ ] Logo + favicon uploaded
- [ ] 5 products imported, digital-delivery configured
- [ ] Homepage sections built to match preview
- [ ] Payment tested (test card) — first real order lands in Sheets
- [ ] (Optional) App installed → 3 deferred webhooks registered

**END — All IP belongs to JDB Sales.**