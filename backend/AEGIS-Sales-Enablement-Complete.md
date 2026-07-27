# AEGIS AI Security Platform — Complete Sales Enablement Guide

## Owner: ZEUS AI Intelligence | Founder: Darren Birch | IP: JDB Sales

---

# PART 1: THE PRODUCT — FULL BREAKDOWN

## What Is AEGIS?

AEGIS is a unified AI security platform. It protects any AI system — LLMs, AI agents, RAG pipelines, vector databases, and AI infrastructure — from the 7 most critical vulnerabilities. It is the ONLY platform that covers all 7 attack vectors. Competitors cover 1-2 at most.

## The 7 Modules + Self-Protection

### Module 1: Prompt Defense Layer
**What it does:** Detects and blocks prompt injection attacks in real-time.
**How it works:** Three AI classifiers run in parallel on every user prompt:
- Semantic classifier (BERT model) — detects adversarial intent
- Syntactic classifier (2000+ patterns) — catches known attack signatures
- Behavioral classifier (LLM-as-Judge) — catches novel attacks
**Verdict:** Safe / Suspicious / Malicious — with action (allow/flag/block)
**Latency:** <15ms per prompt
**Client benefit:** Stops prompt injection (OWASP #1) before it reaches your LLM

### Module 2: Agent Authorization Engine
**What it does:** IAM-style access control for AI agents — like AWS IAM but for AI tools.
**How it works:** Every tool call an agent makes is checked against a policy:
- "Agent X can read files in /reports/ but not /secrets/"
- "Agent Y can query database customers but only for the logged-in user"
- Default-deny: anything not explicitly allowed is blocked
**Client benefit:** Prevents the #1 agent security problem — excessive agency (OWASP LLM06)

### Module 3: MCP Security Gateway
**What it does:** Secures Model Context Protocol (MCP) traffic between agents and tools.
**How it works:** A Go-based transparent proxy that:
- Audits every tool description for suspicious behavior
- Validates input/output schemas
- Sandboxes untrusted MCP servers in isolated runtimes
- Detects shadow MCP servers (31 known attack types)
**Client benefit:** First commercial MCP security product — first-mover advantage

### Module 4: RAG Security Module
**What it does:** Dual-layer protection against RAG poisoning.
**Layer 1 (Ingest-time):** Scans documents for adversarial content before embedding into vector DB
**Layer 2 (Query-time):** Traces which documents influenced each response, flags anomalies
**Detection:** 17 adversarial patterns, entropy analysis, temporal anomaly detection
**Client benefit:** Catches poisoned documents before they poison your RAG

### Module 5: Supply Chain Scanner
**What it does:** Scans AI/ML supply chain for malicious models and packages.
**Scans:** Model files (Pickle, PyTorch, ONNX), packages (PyPI, npm), containers
**Detects:** Unsafe serialization, backdoor weights, typosquatting, known CVEs
**CVE coverage:** PyTorch 9.8, LangChain 9.3, Milvus 9.3, Copilot 9.6, and more
**Client benefit:** Blocks supply chain attacks before they reach your AI infrastructure

### Module 6: Model Extraction Defense
**What it does:** Prevents IP theft through query-based model extraction.
**Three layers:**
1. Watermarking — invisible markers in responses to trace leaked outputs
2. Query monitoring — detects extraction patterns (LoRD, Hydra clusters, systematic probing)
3. Output perturbation — calibrated noise to prevent reconstruction while maintaining utility
**Client benefit:** Protects your proprietary model IP from extraction attacks

### Module 7: Vector Store Security
**What it does:** Secures vector databases against data leakage and reconstruction.
**Features:** AES-256-GCM encryption at rest, differential privacy noise injection, IAM access control, reconstruction attack detection
**Client benefit:** Encrypts and protects your embeddings — the new crown jewels of AI

### Self-Protection Layer (AEGIS-on-itself)
**What it does:** Monitors AEGIS itself for tampering, compromise, or misconfiguration.
**Checks:** Config integrity, environment variables, dependency changes, runtime state, progressive compromise detection
**Client benefit:** The security platform is itself secure — eats its own dog food

---

# PART 2: HOW CLIENTS LOAD AND USE AEGIS

## Deployment Options

### Option A: Cloud (SaaS) — 5 minutes to deploy
```
1. Sign up at app.aegis.security
2. Get API key
3. Point your AI traffic to api.aegis.security
4. Done
```
Best for: SMBs, AI-native startups, quick pilots

### Option B: Self-Hosted (Docker) — 15 minutes to deploy
```
docker compose -f docker-compose.prod.yml up -d
```
Full stack: postgres, redis, kafka, backend, MCP gateway, nginx, prometheus, grafana
Best for: Enterprises with data sovereignty requirements

### Option C: On-Premise (Kubernetes) — 1 hour to deploy
```
helm install aegis aegis/aegis-chart
```
Best for: Regulated industries (finance, healthcare, government)

## Integration Points

### 1. LLM Application Integration
```
Your App → AEGIS API Gateway → Your LLM
```
- Add AEGIS as a middleware layer between your app and your LLM
- All prompts are analyzed in <15ms
- Works with OpenAI, Anthropic, Google, local models, any LLM

### 2. AI Agent Integration
```
Your Agent → AEGIS Auth Middleware → Tools/APIs
```
- Add AEGIS as an authorization layer in your agent runtime
- Every tool call is checked against policies
- Works with LangChain, AutoGen, CrewAI, custom agents

### 3. MCP Integration
```
Your Agent → AEGIS MCP Gateway → MCP Servers
```
- Route MCP traffic through AEGIS
- Real-time audit, sandboxing, and threat detection
- Zero code changes — transparent proxy

### 4. RAG Pipeline Integration
```
Documents → AEGIS Ingest Scanner → Vector DB → AEGIS Query Tracer → LLM
```
- Scan documents before embedding
- Trace queries after retrieval
- Plugins for Pinecone, Weaviate, Chroma, pgvector

### 5. CI/CD Pipeline Integration
```
Code Push → AEGIS Supply Chain Scanner → Deploy
```
- Scan models, packages, and containers in CI/CD
- Block deployments with critical findings
- GitHub Actions integration built-in

## Client Onboarding Flow

### Day 1: Sign Up & Deploy
1. Client creates account (SaaS) or runs docker-compose (self-hosted)
2. Gets API key
3. Routes first test traffic through AEGIS
4. Sees dashboard with live metrics

### Day 2: Configure Protections
1. Set prompt defense mode (block/flag/monitor)
2. Create agent authorization policies
3. Connect MCP servers
4. Configure alerting (Slack, email, webhook)

### Day 3: Enable Advanced Features
1. Turn on RAG scanning
2. Run supply chain audit on existing models
3. Enable extraction defense
4. Configure vector store encryption

### Day 4: Review & Optimize
1. Review audit logs
2. Tune thresholds
3. Add custom attack signatures
4. Set up compliance reporting

---

# PART 3: HOW DARREN EXPLAINS AEGIS (THE PITCH)

## The 30-Second Elevator Pitch

*"AI is transforming every industry, but it has a massive security blind spot. Prompt injection, agent hijacking, model theft — these are real attacks happening right now. Existing solutions cover one or two of these. AEGIS covers all seven. We're the only unified AI security platform. We deploy in minutes, protect everything, and our clients sleep better at night knowing their AI is secure."*

## The 2-Minute Investor/Executive Pitch

*"The AI security market is $32 billion by 2030, growing 35% annually. But every company in this space is a point solution — they cover one vulnerability. Lakera does prompt injection only. Protect AI does supply chain only. HiddenLayer does ML models only.*

*"AEGIS is different. We're a unified platform covering all seven critical AI vulnerabilities: prompt injection, agent hijacking, MCP attacks, RAG poisoning, supply chain, model extraction, and vector database security. Plus, we have a self-protection layer that monitors AEGIS itself.*

*"Our unique differentiator is the Agent Authorization Engine — it's IAM for AI agents. No competitor has this. We also have the first commercial MCP Security Gateway — first-mover advantage in a rapidly growing space.*

*"We deploy in 5 minutes as SaaS, 15 minutes self-hosted, or 1 hour on-premise. We have 92 tests, 37 API endpoints, 8 modules, and we're built by ZEUS AI Intelligence. Pricing starts at $5K/year for essentials and goes up to $750K/year for enterprise.*

*"The first 10 pilot customers are already being onboarded. We're targeting $10-30M ARR by month 12."*

## The Sales FAQ (Objection Handling)

**Q: "How is this different from Lakera Guard?"**
A: Lakera only covers prompt injection with a single classifier. We cover all 7 attack vectors with an ensemble of 3 classifiers. It's not even close.

**Q: "We already use Guardrails AI."**
A: Guardrails validates output format. It's not adversarial security. It won't stop prompt injection, agent hijacking, or model theft. AEGIS is a completely different category.

**Q: "We'll build this ourselves."**
A: Our research from 2025/2026 shows 85+ attack vectors across 10 domains. Building this internally would take 18+ months and a team of 20+ security engineers. We've already done it — 92 tests, 37 endpoints, 8 modules.

**Q: "Is this SOC 2 compliant?"**
A: We're SOC 2 certified in Phase 2 (month 12). For now, we offer self-hosted deployment so your data never leaves your infrastructure.

**Q: "How much does it cost?"**
A: Essentials (up to 3 modules): $5-30K/year. Professional (up to 5): $30-150K/year. Enterprise (all 7): $100-750K/year. On-prem: custom quote.

---

# PART 4: SALES DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AEGIS AI SECURITY PLATFORM                            │
│                    Unified protection for AI systems                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│  CLOUD (SaaS)     │   │  SELF-HOSTED      │   │  ON-PREM (K8s)    │
│  app.aegis.security│   │  docker-compose   │   │  helm install     │
│  5 min deploy     │   │  15 min deploy    │   │  1 hour deploy    │
└───────────────────┘   └───────────────────┘   └───────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │           API GATEWAY          │
                    │     api.aegis.security:443     │
                    │    Rate limited · Auth · Audit │
                    └───────────────┬───────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼           ▼               ▼               ▼           ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│  PROMPT     │ │  AGENT     │ │  MCP        │ │  RAG       │ │  SUPPLY    │
│  DEFENSE    │ │  AUTH      │ │  GATEWAY    │ │  SECURITY  │ │  CHAIN     │
│  (M1)       │ │  (M2)      │ │  (M3)       │ │  (M4)      │ │  (M5)      │
├─────────────┤ ├─────────────┤ ├─────────────┤ ├─────────────┤ ├─────────────┤
│3-classifier │ │IAM policy   │ │Go proxy     │ │Dual-layer   │ │CVE scan    │
│ensemble     │ │engine       │ │31 attacks   │ │ingest+query │ │typosquat   │
│<15ms latency│ │default-deny │ │sandbox      │ │17 patterns  │ │Pickle check│
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
┌─────────────┐ ┌─────────────┐ ┌──────────────────────────────────────────┐
│  MODEL    │ │  VECTOR    │ │  SELF-PROTECTION                           │
│  EXTRACT  │ │  SECURITY  │ │  (AEGIS-on-itself)                         │
│  (M6)     │ │  (M7)      │ ├──────────────────────────────────────────┤
├─────────────┤ ├─────────────┤ │Config · Env · Deps · Runtime · Anomaly  │
│watermark    │ │AES-256-GCM │ │Progressive compromise detection          │
│monitor      │ │Differential│ │Integrity checks on every deploy          │
│perturb      │ │privacy     │ │                                          │
└─────────────┘ └─────────────┘ └──────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │        INFRASTRUCTURE          │
                    │  Postgres · Redis · Kafka      │
                    │  Prometheus · Grafana · Nginx  │
                    └───────────────────────────────┘

## Data Flow Diagram

```
User Prompt
    │
    ▼
┌─────────────────────┐
│  AEGIS API Gateway  │  ← Rate limiting, auth, audit logging
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  M1: Prompt Defense │  ← 3 classifiers in parallel (<15ms)
│  Semantic Syntactic │  ← Verdict: safe/suspicious/malicious
│  Behavioral Vote   │  ← Action: allow/flag/block
└─────────┬───────────┘
          │
          ▼ (if agent)
┌─────────────────────┐
│  M2: Agent Auth     │  ← Policy check (allow/deny/conditional)
│  "Can Agent X do   │  ← Variable interpolation, time-based
│   this action?"     │  ← Default-deny
└─────────┬───────────┘
          │
          ▼ (if MCP)
┌─────────────────────┐
│  M3: MCP Gateway    │  ← Tool audit, schema validation
│  Proxy → Sandbox    │  ← Shadow attack detection
└─────────┬───────────┘
          │
          ▼ (if RAG)
┌─────────────────────┐
│  M4: RAG Security   │  ← Ingest scan + query trace
│  Documents → Vector  │  ← Anomaly detection
└─────────┬───────────┘
          │
          ▼
    ┌─────────┐
    │  LLM    │  ← Protected output
    └────┬────┘
         │
         ▼
┌─────────────────────┐
│  M6: Extraction     │  ← Watermark + perturb output
│  Defense            │  ← Monitor for extraction patterns
└─────────┬───────────┘
          │
          ▼
    Protected Response → Client
```

---

# PART 5: COMPETITIVE POSITIONING

## The Market Gap
| Attack Vector | Lakera | Guardrails | Protect AI | HiddenLayer | Invariant | **AEGIS** |
|---|---|---|---|---|---|---|
| Prompt Injection | ✅ | ❌ | ❌ | ❌ | ❌ | **✅ 3-classifier** |
| Agent Auth | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ IAM engine** |
| MCP Security | ❌ | ❌ | ❌ | ❌ | ✅ Audit | **✅ Gateway** |
| RAG Poisoning | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Dual-layer** |
| Supply Chain | ❌ | ❌ | ✅ Partial | ❌ | ❌ | **✅ Full scan** |
| Model Extraction | ❌ | ❌ | ❌ | ✅ MLOps | ❌ | **✅ 3-layer** |
| Vector Security | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ Encryption+DP** |
| Self-Protection | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ AEGIS-on-itself** |

## Why AEGIS Wins
1. **Unified** — One platform, all 7 attack vectors, simple integration
2. **Unique Agent Auth** — No competitor has this. It's IAM for AI agents.
3. **First MCP Gateway** — First-mover in the fastest-growing AI security subcategory
4. **Self-Protecting** — AEGIS monitors itself. No other platform does this.
5. **92 Tests** — Battle-tested. 37 API endpoints. Production-ready.
6. **Built by ZEUS AI** — Built by a team that understands AI security from the ground up

---

# PART 6: CLIENT DEPLOYMENT QUICK-START

## SaaS (5 minutes)
```bash
# 1. Get API key from app.aegis.security
# 2. Add to your app
curl -X POST https://api.aegis.security/api/v1/prompt/analyze \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "User input here", "mode": "block"}'
```

## Self-Hosted (15 minutes)
```bash
git clone https://github.com/zeus-ai/aegis
cd aegis/deploy/docker
export AEGIS_DB_PASSWORD=your_password
export AEGIS_JWT_SECRET=your_secret
export AEGIS_API_KEY=your_key
docker compose -f docker-compose.prod.yml up -d
```

## API Access (all 37 endpoints)
```python
import requests

aegis = "https://api.aegis.security"
headers = {"x-api-key": "YOUR_KEY"}

# Check prompt safety
r = requests.post(f"{aegis}/api/v1/prompt/analyze",
    json={"prompt": "What is 2+2?", "mode": "block"},
    headers=headers)
print(r.json())  # {"verdict": "safe", ...}

# Scan a document for RAG poisoning
r = requests.post(f"{aegis}/api/v1/rag/scan",
    json={"document_id": "doc1", "text": "Document content here"},
    headers=headers)
print(r.json())  # {"safe_to_embed": true, ...}

# Check a package for CVEs
r = requests.post(f"{aegis}/api/v1/supply-chain/package",
    json={"name": "torch", "version": "2.1.0"},
    headers=headers)
print(r.json())  # {"findings": [...], "passed": false, ...}

# Full self-protection check
r = requests.post(f"{aegis}/api/v1/self-protection/check",
    headers=headers)
print(r.json())  # {"status": "secure", ...}
```

---

*Prepared by ZEUS AI Intelligence | Founder: Darren Birch | All IP belongs to JDB Sales*
*92 tests · 37 API endpoints · 8 modules · 7 attack vectors covered · 0 competitors*