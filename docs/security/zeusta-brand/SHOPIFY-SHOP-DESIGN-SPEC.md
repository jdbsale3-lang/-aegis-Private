# ZEUSTA SHOPIFY SHOP-FRONT DESIGN SPEC
**Version 1.0 · 30 Aug 2026 · All IP belongs to JDB Sales**

## Objective
A dark, premium, security-grade storefront that sells 5 digital products. "Trust, engineered." — calm, precise, no hype.

## Theme setup (2 min in admin)
1. **Theme:** Online Store → Themes → use **Dawn** (free) as base → Customize.
2. **Colors (Theme settings → Colors):**
   - Background: `#10131B` · Card background: `#1B2030`
   - Text/headings: `#FFFFFF` · Subtext: `#9AA0AC`
   - Buttons/accent: `#4FCEE4` (hover `#2FA8C3`) · accent 2 (badges): `#D9F24B`
3. **Typography:** Headings — Inter/Archivo Black; Body — Inter; Price/CODE — monospace.
4. **Favicon + store avatar:** upload `zeusta-social-square.svg`.
5. **Logo (header/footer):** upload `zeusta-logo-master.svg` (dark-transparent version from the brand kit).

## Homepage sections (top → bottom)
1. **Announcement bar** (acid yellow text on obsidian): "★ Digital delivery — instant · AI-guarded by AEGIS · Secure checkout via Stripe"
2. **Hero:** full-bleed dark; headline "The AI-Guarded Digital Economy"; subline "Five instant-delivery digital products engineered under the ZEUSTA trust framework."; cyan gradient CTA **Shop the collection**; subtle hex-shield graphic (royalty-free vector, no text).
3. **Trust band** (4 icons, cyan): Instant delivery · Stripe secured · AEGIS-protected downloads · Built by JDB Sales / ZEUSTA
4. **Featured products:** the 5 digital products as cards (obsidian cards, cyan hover ring, acid badge "Digital download").
5. **Benefits section:** Why ZEUSTA — security-grade engineering, immediate fulfilment, lifetime updates, licence clarity.
6. **How it works** (4 steps): Purchase → instant link → download → licensed use.
7. **Testimonial/quote block:** placeholder (Darren supplies).
8. **FAQ:** delivery, licence, refunds (14-day digital-goods policy wording), support email.
9. **Footer:** logo, "All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD · CH 17391549", payment icons, small print.

## Product cards (consistent system)
- Dark backdrop `#10131B` → cyan glow ring on hover → acid "INSTANT DELIVERY" badge
- Name (white, Inter Black) · one-line descriptor (muted) · price GBP (cyan) · compare-at price struck
- CTA: **Add to cart** (cyan) — one yellow CTA per view max

## Checkout notes
- Digital products: **no shipping** — Shopify digital download app (ex. "Digital Downloads") or manual fulfilment via email link for now; enable "Requires shipping = no" per product.
- Currency GBP. Payment via existing Stripe payment link setup or Shopify Payments.
- After first sale: flip the webhook → receipts flow already wired.

## Applied-once checklist
- [ ] Dawn theme active, colours/typography per above
- [ ] Logo + favicon uploaded (brand kit)
- [ ] 5 products published (from `zeusta-shopify-products.csv`) with covers
- [ ] Announcement bar + hero + trust band + sections per spec
- [ ] Test checkout with a $0/£1 test OR Stripe test card 4242 4242 4242 4242

**END — All IP belongs to JDB Sales.**