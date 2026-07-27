# AEGIS Sales Diagram & Explainer Guide
## How Darren Birch Pitches AEGIS

---

## THE ONE-PAGE SALES DIAGRAM (Text Version)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    🛡️  AEGIS AI SECURITY PLATFORM                     │
│              Unified Protection for Any AI System                    │
│              Owner: ZEUS AI Intelligence  |  Founder: Darren Birch   │
└─────────────────────────────────────────────────────────────────────┘

                         YOUR APPLICATION
                              │
                              ▼
                    ┌─────────────────┐
                    │  AEGIS GATEWAY  │  ← 5 min setup
                    │  (api.aegis.security) │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  BEFORE LLM    │ │  DURING AGENT  │ │  AFTER OUTPUT  │
│  Prompt Safety │ │  Tool Security │ │  IP Protection │
├─────────────────┤ ├─────────────────┤ ├─────────────────┤
│  M1: Prompt     │ │  M2: Agent Auth │ │  M6: Extraction │
│  Defense        │ │  M3: MCP Gateway│ │  Defense        │
│  ┌───────────┐  │ │  ┌───────────┐  │ │  ┌───────────┐  │
│  │Semantic   │  │ │  │Policy     │  │ │  │Watermark  │  │
│  │Classifier │  │ │  │Engine     │  │ │  │Output     │  │
│  ├───────────┤  │ │  ├───────────┤  │ │  ├───────────┤  │
│  │Syntactic  │  │ │  │Default    │  │ │  │Monitor    │  │
│  │Classifier │  │ │  │Deny       │  │ │  │Patterns   │  │
│  ├───────────┤  │ │  ├───────────┤  │ │  ├───────────┤  │
│  │Behavioral │  │ │  │Audit Log  │  │ │  │Perturb    │  │
│  │Judge      │  │ │  │           │  │ │  │Output     │  │
│  └───────────┘  │ │  └───────────┘  │ │  └───────────┘  │
└─────────────────┘ └─────────────────┘ └─────────────────┘

┌─────────────────┐ ┌─────────────────┐ ┌──────────────────────┐
│  INFRASTRUCTURE │ │  DATA CHAIN    │ │  SELF-PROTECTION     │
├─────────────────┤ ├─────────────────┤ ├──────────────────────┤
│  M4: RAG        │ │  M5: Supply     │ │  AEGIS-on-itself     │
│  Security       │ │  Chain Scanner  │ │  ┌────────────────┐  │
│  ┌───────────┐  │ │  ┌───────────┐  │ │  │Config Integrity│  │
│  │Ingest Scan│  │ │  │Model Scan │  │ │  │Env Check      │  │
│  ├───────────┤  │ │  ├───────────┤  │ │  │Dependency     │  │
│  │Query Trace│  │ │  │Package    │  │ │  │Runtime State  │  │
│  ├───────────┤  │ │  │CVE Check  │  │ │  │Anomaly Detect │  │
│  │Anomaly    │  │ │  ├───────────┤  │ │  └────────────────┘  │
│  │Detect     │  │ │  │Typosquat  │  │ │                      │
│  └───────────┘  │ │  └───────────┘  │ │  M7: Vector Store    │
│                 │ │                 │ │  ┌────────────────┐  │
│                 │ │                 │ │  │Encryption      │  │
│                 │ │                 │ │  │Differential   │  │
│                 │ │                 │ │  │Privacy        │  │
│                 │ │                 │ │  │Access Control │  │
│                 │ │                 │ │  └────────────────┘  │
└─────────────────┘ └─────────────────┘ └──────────────────────┘

              DEPLOYMENT OPTIONS
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │  SaaS    │  │  Docker  │  │  On-Prem │
    │  5 min   │  │  15 min  │  │  1 hour  │
    │  $5K/yr  │  │  $30K/yr │  │  Custom  │
    └──────────┘  └──────────┘  └──────────┘
```

---

## THE THREE PITCHES (For Different Audiences)

### 1. The CISO Pitch (30 seconds)
*"Your AI systems are vulnerable to 7 attack vectors. Every vendor covers one. We cover all seven. One platform, one integration, one bill. Deploy in minutes."*

### 2. The Technical Pitch (2 minutes)
*"We sit between your application and your LLM. Every prompt hits our 3-classifier ensemble — semantic, syntactic, behavioral — in under 15 milliseconds. If you have AI agents, we have an IAM-style policy engine that controls every tool call. If you use MCP, we have the first commercial MCP security gateway. If you have RAG, we scan documents before embedding and trace queries after retrieval. Supply chain, model extraction, vector security — we cover it all. 37 API endpoints, 92 tests, self-protecting."*

### 3. The Business Pitch (1 minute)
*"The AI security market is $32 billion by 2030. Every competitor is a point solution. We're the only unified platform. We have a unique differentiator — Agent Authorization — that no one else has. First MCP security product on the market. We deploy in 5 minutes as SaaS, 15 minutes self-hosted. Pricing from $5K to $750K per year. We're targeting $10-30M ARR in year one."*

---

## THE ONE-LINE EXPLAINERS

| Question | Answer |
|---|---|
| What is AEGIS? | "Unified AI security — one platform that protects all 7 AI attack vectors." |
| How is it different? | "Every competitor covers 1-2 vectors. We cover all 7. It's not close." |
| Who needs it? | "Any company using AI in production. LLMs, agents, RAG, vector databases." |
| How fast to deploy? | "5 minutes SaaS, 15 minutes self-hosted, 1 hour on-prem." |
| How much? | "Starts at $5K/year. Enterprise at $100-750K/year." |
| What makes it special? | "Agent Authorization Engine — IAM for AI agents. No one else has this." |
| Is it secure? | "It protects itself. Self-protection layer monitors for tampering." |
| Who built it? | "ZEUS AI Intelligence. Darren Birch. 92 tests, 37 endpoints, production-ready." |

---

## SALES PROCESS FLOW

```
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  Lead    │→│  Demo   │→│  Pilot  │→│  Close  │→│  Onboard │
│  Identify│  │  (15min)│  │  (30day)│  │  (Deal) │  │  (Day 1) │
└──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘
     │             │             │             │             │
     ▼             ▼             ▼             ▼             ▼
  Research    Show product   Self-host or   Quote based  Deploy with
  their AI    live: run      SaaS with      on modules   guided
  usage +     prompt test,   their own      + tier:      onboarding:
  security     show agent     data. Free     Essentials   Day 1 setup
  posture      auth, scan    tier for       $5-30K/yr    Day 2 config
               their deps    30 days.       Professional Day 3 advanced
                                            $30-150K/yr  Day 4 optimize
                                            Enterprise
                                            $100-750K/yr
```

---

## KEY SALES NUMBERS TO MEMORIZE

| Metric | Number |
|---|---|
| Market size (2030) | $32B TAM |
| CAGR | 35% |
| AI security pure-play (2026) | $3.62B |
| AI security pure-play (2031) | $14.47B |
| Competitors covering all 7 | 0 |
| AEGIS attack vectors covered | 7 + self-protection |
| Tests passing | 92 |
| API endpoints | 37 |
| Modules | 8 |
| Deploy time (SaaS) | 5 minutes |
| Deploy time (self-hosted) | 15 minutes |
| Pricing range | $5K - $750K/year |
| Target ARR (month 12) | $10-30M |
| Target ARR (month 18) | $50-100M |

---

## COMPETITIVE ONE-LINERS

| When they say... | You say... |
|---|---|
| "We use Lakera" | "Lakera only covers prompt injection with a single classifier. We use 3 classifiers and cover 7 attack vectors." |
| "We use Guardrails" | "Guardrails validates output format. It's not security. It won't stop an attack." |
| "We use Protect AI" | "Protect AI only covers supply chain. What about prompt injection, agent hijacking, and model theft?" |
| "We'll build it" | "It took us 8 modules and 92 tests to cover everything. Building this internally would take 18+ months." |
| "We're not big enough" | "You don't need to be big to be attacked. AI agents are the #1 fastest-growing attack surface." |
| "Show me the ROI" | "One prompt injection breach costs an average of $4.5M. AEGIS starts at $5K/year. That's 900x ROI." |