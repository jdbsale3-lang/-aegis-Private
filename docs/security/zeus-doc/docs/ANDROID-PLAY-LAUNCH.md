# ZEUS ANDROID — PLAY CONSOLE AUDIT & LAUNCH CHECKLIST
**30 Aug 2026 · All IP belongs to JDB Sales · ZEUSTRUSTAEGISSECURITY LTD**

## 1. ACCOUNT (verified from Darren's Play Console)
| Field | Value |
|---|---|
| Developer account | https://play.google.com/console/u/0/developers/8152816830862058718/account |
| Developer ID | 8152816830862058718 |
| Apps registered | 2 (both 4 Jul 2026) |

## 2. THE TWO APPS — REGISTERED, NOT PUBLISHED
| App | Package (current) | Points to note |
|---|---|---|
| **ZEUS Calorie Lens** (com.zeusaiintellegence.myapp) | `com.zeusaiintellegence.myapp` | ⚠️ **Not on public Play Store** (verified "Not Found") — requires listing + publish |
| **ZEUS / ForgeFit** (com.zeusaiintellegence) | `com.zeusaiintellegence` | ⚠️ **Not on public Play Store** (verified "Not Found") — requires listing + publish |

**Critical: package-name typo.** Both packages use `zeusaiintellegence` (double‑L, missing "i") — same typo as the `zeusaiintellegence.store/.co.uk` domains. **Android package names cannot be renamed after the first production release.** Options:
- **Option A (recommended):** keep these two for now but create NEW applications with correct packages (`com.zeusaiintelligence.myapp`, `com.zeusaiintelligence`) before any public release — correct spelling goes live, typo packages are deleted/discarded.
- **Option B:** publish with the typo and regret it later (branding consistency problem for ZEUS/ZEUSTRUSTA).
Recommendation: fix BEFORE publishing. This is a 10-minute console task, far cheaper than a re-release.

## 3. WHAT "PUBLISHED" REQUIRES (per app, in console)
1. **Store listing** — title, short/full description, icon, feature graphic (1024×500), screenshots (phone ≥2; tablet optional), app category, contact email (jdbsale3@gmail.com), privacy policy URL (we can host on zeustrustaegissecurity.higgsfield.app)
2. **Content rating** — questionnaire (approx 15 min/app)
3. **Data safety** — declare data collected (health/calorie data → UK GDPR implications; AEGIS posture helps)
4. **Target audience** — 13+, no ads default
5. **App access / ads** — declare ads if any (none by default)
6. **Release — production track** — upload signed AAB/APK (or use Play App Signing), rollout 100%
7. **Signing** — use **Play App Signing** (Google-managed) or keystore (keep safe — losing keystore = unable to update; Play App Signing avoids this)
8. **Pricing** — set price per app (Paid apps): "all paid for" per Darren → set price in GBP (e.g., Calorie Lens £2.99, ForgeFit £4.99 — user confirms)
9. **Payment** — Google Play payout account (bank details for merchant earnings) — must be set in Payments profile
10. **Publication** — click "Publish" on the release; Google review takes hours–days

**Pre-launch quality gates (what ZEUS prepares):**
- Privacy policy / data-safety copy — drafted on request
- Feature graphic + icon — we have brand assets; can generate compliant sizes
- Store descriptions (SEO keywords) — drafted on request

## 4. WHAT ZEUS CANNOT DO (honest)
- Cannot log into your Play Console (Google login + 2FA — your browser only)
- Cannot upload APKs or click Publish (console is single-sign-on protected)
- **What ZEUS CAN do:** build the buy-pages + product copy on zeus-store.higgsfield.app linking to your Play listings, prepare privacy policy/screenshots copy, and track the Play links via the `/go/` tracker — so the moment you hit Publish, everything is ready.

## 5. RECOMMENDED NEXT ACTIONS (this week)
1. **Decide the package-name typo fix** (Option A) — create correct packages now
2. Give me the **APK/AAB paths or a Dropbox/Drive link** — I can't push to Play, but I can prepare the release notes + versioning
3. Confirm **prices** (Calorie Lens / ForgeFit GBP) and I'll wire the store pages
4. I draft the **privacy policy + data-safety + store copy** — ready to paste into the console
5. Once you click Publish, update me — I'll verify the public listings and flip the store pages live

**END — All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.**