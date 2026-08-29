# AEGIS AI SECURITY — GOING-FORWARD OPERATING COSTS
**29 Aug 2026 · All IP belongs to JDB Sales.** Prices verified against vendor sites on 29 Aug 2026.

---

## 1. MUST-KEEP (production infrastructure — AEGIS cannot run without these)

| Service | What it runs | Price | Billing notes |
|---|---|---|---|
| **DigitalOcean Droplet** | AEGIS API server (aegis-api, Ubuntu 24.04, systemd+venv+nginx, PostgreSQL 16) | **$6.00/mo** | 1 GiB RAM / 1 vCPU / 25 GiB SSD plan. Per-second billing since Jan 2026, capped at 672h = $6 flat. On 33 GiB disk — watch: 70% used. |
| **Domains** | zeusaiintelligence.com + apiaegissecurity.tech | **~$10–15/yr each** (.com), **~$33/yr** (.tech) | .com renewal: Namecheap $14.78, Spaceship $10.18, Cloudflare registrar $10.46. Verisign wholesale rising to $10.97 on 1 Nov 2026. .tech renewals are expensive (~$33). |
| **Cloudflare (Free plan)** | DNS, proxy, tunnel (cloudflared to your PC), WAF basics, Workers Free (100k req/day) | **$0.00/mo** | Your usage (tunnel + DNS + managed transforms) fits Free. Upgrade to Workers Paid only if >100k req/day: $5/mo min. |
| **AWS S3 (backups)** | Off-site backup archive `zeus-aegis-backups` (eu-west-2) | **~$0.25–0.50/mo** | ~9.5 GiB stored ≈ $0.22/mo at $0.023/GiB; plus GET/PUT cents. Negligible. |

**Must-keep subtotal: ≈ $6.50–7/mo + ~$55/yr domains (~$4.60/mo)  ≈ $11/mo all-in.**

## 2. DEVELOPMENT / DELIVERY TOOLS (keep for building & CI)

| Service | What it runs | Price | Notes |
|---|---|---|---|
| **GitHub** (repo `-aegis-Private`) | Source, CI/CD (7 checks + CodeQL + deploy), Dependabot, branch protection | **$0.00/mo** | GitHub Free now includes **unlimited private repos + unlimited collaborators + 2,000 Actions min/month** for private. Your CI (~10 min × ~10 runs/day ≈ 3,000+ min) can exceed Free at heavy use → **GitHub Team $4/user/mo incl. 3,000 Actions min** (first-12-months promo). Recommended: upgrade when Actions minutes run out. |
| **Anthropic Claude** (API) | **Optional** — dev-assist / LLM features if you wire it into ZEUS/AEGIS tooling | **Pay-as-you-go**: Opus 5 $5/MTok in, $25/MTok out; Sonnet-class ~$3/$15 | AEGIS itself does NOT call Claude at runtime. Only pay if you use it for development/analysis. If used lightly (<1M tokens/mo): **$0–10/mo**. |
| **Hugging Face** | Model hosting/downloads (transformers base models if you enable ML modes) | **$0.00** (public models) | Free downloads of public weights; paid only for private model repos / Pro ($9/mo) if you host proprietary models. |
| **GitHub Actions runner** | CI minutes | part of GitHub plan | Public runner minutes are free for public repos; private repo minutes come from the plan above. |

## 3. COMMUNICATION / OPS (what you already pay or may want)

| Service | Used for | Price |
|---|---|---|
| Google Workspace / Gmail | Business email, connector | $0 (current Gmail) to $7.20/user/mo (Workspace Business Starter) |
| X / LinkedIn / TikTok / IG | Social publishing (connectors already connected) | $0 |
| Notion (connector) | Docs/knowledge | Free personal to $10/user/mo (Plus) |
| Slack (connector) | Team messaging | Free to $7.25/user/mo (Pro) |
| OpenAI/other LLMs | Only if you add them | N/A unless enabled |

## 4. MONTHLY RUNNING TOTAL (recommended baseline)

| Category | Monthly |
|---|---|
| Production infra (DO + S3 + CF) | ~$7 |
| Domains (amortised) | ~$4.60 |
| GitHub (Free now; Team when needed) | $0 → $4 |
| Claude (optional dev) | $0–10 |
| **Baseline total** | **~$12–25/mo** |

## 5. WHAT COULD CATCH YOU (watch these)

- **Disk pressure**: droplet at 70% — backups tar 1.7–2.6 GiB/day. Keep the 7-day retention; if S3 grows, prune old tarballs. Consider $12/mo 2GB droplet if DB grows.
- **Domains**: renew **before** expiry (auto-renew ON) — a lapsed zeusaiintelligence.com breaks the whole demo.
- **Cloudflare tunnel**: now a boot-safe service on your PC — keep it running; no cost.
- **GitHub Actions minutes**: if CI exceeds Free's 2,000 min, jobs fail — upgrade to Team ($4/mo) before NHS demo week if you're CI-heavy.

**END — All IP belongs to JDB Sales.**