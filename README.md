# AEGIS — AI Security & Guardian Intelligence System

**Owner:** ZEUS AI Intelligence
**Founder:** Darren Birch
**IP:** JDB Sales
**Contact:** jdbsale3@gmail.com

---

## What Is AEGIS?

AEGIS is the **only unified AI security platform** covering all 7 critical AI attack vectors. Every competitor covers 1-2. AEGIS covers all 7 + self-protection.

| Attack Vector | OWASP | AEGIS Module |
|---|---|---|
| Prompt Injection | LLM01 | 3-classifier ensemble (<15ms) |
| Excessive Agency | LLM06 | IAM policy engine (unique) |
| MCP Attacks | Emerging | First commercial MCP gateway |
| RAG Poisoning | LLM04 | Dual-layer ingest+query |
| Supply Chain | LLM03 | CVE + typosquatting scanner |
| Model Extraction | LLM07 | Watermark + monitor + perturb |
| Vector Security | LLM08 | Encryption + DP + access control |
| Self-Protection | — | AEGIS-on-itself |

## Quick Start

### Option 1: Local API Server (no database needed)
```bash
cd backend
pip install -r requirements.txt
python api_server.py
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

### Option 2: Full Stack (Docker)
```bash
cd deploy/docker
export AEGIS_DB_PASSWORD=your_password
export AEGIS_JWT_SECRET=your_secret
export AEGIS_API_KEY=your_key
docker compose -f docker-compose.prod.yml up -d
```

### Option 3: SaaS
Visit https://aegis-security.higgsfield.app

## API Overview

### Module 1: Prompt Defense
```bash
curl -X POST http://localhost:8000/api/v1/prompt/analyze \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is 2+2?", "mode": "block"}'
# → {"verdict": "safe", "action": "allow", "latency_ms": 3.4}
```

### Module 2: Agent Authorization
```bash
curl -X POST http://localhost:8000/api/v1/agent/authorize \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "test", "tool_call": {"tool": "read_file", "params": {"path": "/reports/public/report.pdf"}}}'
```

### Module 4: RAG Security
```bash
curl -X POST http://localhost:8000/api/v1/rag/scan \
  -H "Content-Type: application/json" \
  -d '{"document_id": "doc1", "text": "Safe document content"}'
# → {"safe_to_embed": true, "risk_score": 0.0}
```

### Module 5: Supply Chain
```bash
curl -X POST http://localhost:8000/api/v1/supply-chain/package \
  -H "Content-Type: application/json" \
  -d '{"name": "torch", "version": "2.1.0"}'
# → {"passed": false, "findings": [{"cve": "CVE-2026-24747", "cvss": 9.8}]}
```

### Module 8: Self-Protection
```bash
curl -X POST http://localhost:8000/api/v1/self-protection/check
# → {"status": "secure", "overall_score": 0.0}
```

## 37 API Endpoints

| Route | Module | Method |
|---|---|---|
| /api/v1/prompt/analyze | M1 | POST |
| /api/v1/prompt/batch | M1 | POST |
| /api/v1/prompt/signatures | M1 | GET |
| /api/v1/agent/authorize | M2 | POST |
| /api/v1/agent/policies | M2 | GET/POST |
| /api/v1/rag/scan | M4 | POST |
| /api/v1/rag/trace | M4 | POST |
| /api/v1/rag/batch-scan | M4 | POST |
| /api/v1/supply-chain/model | M5 | POST |
| /api/v1/supply-chain/package | M5 | POST |
| /api/v1/supply-chain/requirements | M5 | POST |
| /api/v1/extraction-defense/watermark | M6 | POST |
| /api/v1/extraction-defense/monitor | M6 | POST |
| /api/v1/extraction-defense/full-defense | M6 | POST |
| /api/v1/vector-security/encrypt | M7 | POST |
| /api/v1/vector-security/decrypt | M7 | POST |
| /api/v1/vector-security/access/check | M7 | POST |
| /api/v1/vector-security/policy | M7 | POST |
| /api/v1/vector-security/detect-reconstruction | M7 | POST |
| /api/v1/self-protection/check | SELF | POST |
| /api/v1/self-protection/runtime-state | SELF | POST |
| /api/v1/self-protection/reset-baseline | SELF | POST |
| /api/v1/advanced/multi-modal | ADV | POST |
| /api/v1/advanced/watermark/lord-resistant | ADV | POST |
| /api/v1/advanced/vectorpin/create | ADV | POST |
| /api/v1/advanced/vectorpin/verify | ADV | POST |
| /api/v1/advanced/audit/milvus | ADV | POST |
| /api/v1/advanced/audit/langchain | ADV | POST |
| /health | ALL | GET |

## Test Suite
```bash
cd backend
python -m pytest tests/ -v
# 92 tests, all passing
```

## Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    AEGIS API GATEWAY                         │
│                     localhost:8000                           │
├─────────────────────────────────────────────────────────────┤
│  M1: Prompt Defense  │  M2: Agent Auth  │  M3: MCP Gateway  │
│  (3-classifier)      │  (IAM engine)    │  (Go proxy)       │
├──────────────────────┼──────────────────┼───────────────────┤
│  M4: RAG Security    │  M5: Supply Chain│  M6: Extraction   │
│  (dual-layer)        │  (CVE scanner)   │  (watermark)      │
├──────────────────────┼──────────────────┼───────────────────┤
│  M7: Vector Security │  Self-Protection │  Advanced Defenses│
│  (encryption+DP)     │  (AEGIS-on-itself)│  (multi-modal+)  │
└──────────────────────┴──────────────────┴───────────────────┘
```

## Pricing
| Tier | Price | Modules |
|---|---|---|
| Essentials | $5K-$30K/yr | Up to 3 |
| Professional | $30K-$150K/yr | Up to 5 |
| Enterprise | $100K-$750K/yr | All 7 |

## Deployment
- **SaaS:** 5 minutes — https://aegis-security.higgsfield.app
- **Self-hosted:** 15 minutes — `docker compose up -d`
- **On-prem:** 1 hour — `helm install aegis`

## Project Structure
```
aegis-mvp/
├── backend/
│   ├── api_server.py          # Standalone API server (no DB)
│   ├── main.py                # Full server (with DB)
│   ├── core/                  # Config, database, security middleware
│   ├── models/                # SQLAlchemy models
│   ├── modules/               # 8 security modules
│   │   ├── prompt_defense/    # M1: 3-classifier ensemble
│   │   ├── agent_auth/        # M2: IAM policy engine
│   │   ├── rag_security/      # M4: Dual-layer RAG
│   │   ├── supply_chain/      # M5: CVE + typosquatting scanner
│   │   ├── model_extraction/  # M6: Watermark + monitor + perturb
│   │   ├── vector_security/   # M7: Encryption + DP + access control
│   │   ├── self_protection/   # AEGIS-on-itself
│   │   └── advanced_defenses/ # Multi-modal, LoRD, VectorPin, CVEs
│   └── tests/                 # 92 tests
├── gateway/                   # M3: Go MCP Gateway
├── deploy/docker/             # Docker Compose, nginx, Dockerfiles
├── scripts/                   # deploy.sh
└── docs/                      # Sales enablement documentation
```

## Sales Enablement Docs
- AEGIS-Sales-Enablement-Complete.md — Full product breakdown + pitch
- AEGIS-Sales-Diagram-Explainer.md — Visual diagram + 3 pitch versions
- AEGIS-Client-Onboarding-Guide.md — Day 1-4 client onboarding
- AEGIS-Live-Demo-Script.md — 6 copy-paste Python demos
- AEGIS-Pricing-Proposal-Template.md — Pricing + proposal template
- AEGIS-Go-To-Market-Plan.md — 4-phase 18-month launch plan
- AEGIS-Product-Brief.md — Executive summary
- AEGIS-Technical-Architecture.md — Deep architecture spec

## Competitive Advantage
| Competitor | Vectors | AEGIS Advantage |
|---|---|---|
| Lakera Guard | 1 (prompt only) | 7 vectors + 3-classifier vs 1 |
| Guardrails AI | 0 (output format) | Adversarial security |
| Protect AI | 1 (supply chain) | All 7 + unified |
| HiddenLayer | 1 (ML models) | LLM + agent + MCP + RAG |
| Invariant Labs | 1 (MCP audit) | Runtime + all others |