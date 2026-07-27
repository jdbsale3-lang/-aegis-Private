# AEGIS Client Onboarding Guide
## How Clients Load, Integrate, and Use AEGIS

---

## PHASE 1: DAY 1 — SIGN UP & DEPLOY

### Option A: SaaS (5 minutes)
```bash
# Step 1: Sign up
# Go to https://app.aegis.security
# Create account with email
# Verify email
# Copy API key from dashboard

# Step 2: Test the API
curl -X POST https://api.aegis.security/api/v1/prompt/analyze \
  -H "x-api-key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What is the capital of France?", "mode": "monitor"}'

# Step 3: View dashboard
# Open https://app.aegis.security/dashboard
# See live metrics, request counts, blocked threats
```

### Option B: Self-Hosted via Docker (15 minutes)
```bash
# Step 1: Get the code
git clone https://github.com/zeus-ai/aegis
cd aegis/deploy/docker

# Step 2: Set environment variables
export AEGIS_DB_PASSWORD=$(openssl rand -hex 32)
export AEGIS_REDIS_PASSWORD=$(openssl rand -hex 32)
export AEGIS_JWT_SECRET=$(openssl rand -hex 32)
export AEGIS_API_KEY=$(openssl rand -hex 32)
export AEGIS_CORS_ORIGINS="https://app.yourcompany.com"

# Step 3: Deploy
docker compose -f docker-compose.prod.yml up -d

# Step 4: Verify
curl http://localhost:8000/health
# Returns: {"service": "AEGIS", "status": "healthy", "modules": {...}}
```

### Option C: On-Prem via Kubernetes (1 hour)
```bash
# Step 1: Add Helm repo
helm repo add aegis https://charts.aegis.security
helm repo update

# Step 2: Install
helm install aegis aegis/aegis-chart \
  --set database.password=YOUR_PASSWORD \
  --set jwt.secret=YOUR_SECRET \
  --set api.key=YOUR_KEY

# Step 3: Verify
kubectl get pods -n aegis
# All pods should be Running
```

---

## PHASE 2: DAY 1 — INTEGRATION

### Integration 1: LLM Application
AEGIS sits between your app and your LLM as a middleware layer.

**Before (no AEGIS):**
```
User → Your App → LLM → Response
```

**After (with AEGIS):**
```
User → Your App → AEGIS Gateway → LLM → AEGIS Watermark → Response
                    │                    │
                    ▼                    ▼
              Prompt checked       Output protected
              for injection        from extraction
```

**Code change required:** Add one API call per prompt
```python
import requests

def call_llm_safely(user_prompt, llm_api_func):
    # Step 1: Check prompt with AEGIS
    aegis = requests.post(
        "https://api.aegis.security/api/v1/prompt/analyze",
        json={"prompt": user_prompt, "mode": "block"},
        headers={"x-api-key": "YOUR_KEY"}
    )
    result = aegis.json()
    
    if result["action"] == "block":
        return {"error": "Prompt blocked by security policy", "reason": result["verdict"]}
    
    # Step 2: Call LLM (only if prompt is safe)
    response = llm_api_func(user_prompt)
    
    # Step 3: Protect output from extraction
    protected = requests.post(
        "https://api.aegis.security/api/v1/extraction-defense/watermark",
        json={"output": response},
        headers={"x-api-key": "YOUR_KEY"}
    )
    return protected.json()["watermarked_output"]
```

### Integration 2: AI Agent
AEGIS checks every tool call your agent makes.

**Before (no AEGIS):**
```
Agent → Tool Call → Any Tool → Result
```

**After (with AEGIS):**
```
Agent → AEGIS Auth → Tool Call → Result
         │
         ▼
    Policy check:
    "Can this agent
     call this tool
     with these params?"
```

**Code change required:** Add AEGIS middleware to your agent runtime
```python
from aegis import AEGISAgent

# Wrap your agent with AEGIS
agent = AEGISAgent(
    agent_id="customer-support-agent",
    api_key="YOUR_KEY",
    policies=[
        {
            "path": "filesystem:/reports/public/*",
            "actions": ["read_file"],
            "conditions": [{"key": "file.size_mb", "operator": "lte", "value": "10"}]
        }
    ]
)

# Use the agent as normal — AEGIS handles authorization
response = agent.run("Read the Q1 report")
```

### Integration 3: MCP Servers
AEGIS sits between your agent and MCP servers.

**Before (no AEGIS):**
```
Agent → MCP Server → Tool Result
```

**After (with AEGIS):**
```
Agent → AEGIS MCP Gateway → MCP Server → Tool Result
         │
         ▼
    Tool audit, schema validation,
    sandboxed execution, shadow detection
```

**Code change required:** Change your MCP endpoint
```bash
# Instead of connecting directly to mcp://my-server:8080
# Connect through AEGIS:
docker run -p 8443:8443 \
  -e AEGIS_MCP_MODE=gateway \
  -e AEGIS_MCP_UPSTREAM=mcp://my-server:8080 \
  aegis/mcp-gateway:latest

# Now connect to localhost:8443 instead
```

### Integration 4: RAG Pipeline
AEGIS scans documents before embedding and traces queries after retrieval.

**Before (no AEGIS):**
```
Document → Embed → Vector DB → Query → LLM
```

**After (with AEGIS):**
```
Document → AEGIS Scan → Embed → Vector DB → AEGIS Trace → LLM
             │                              │
             ▼                              ▼
        Poisoning check               Anomaly detection
```

**Code change required:** Add two API calls
```python
import requests

def ingest_document_safely(doc_id, text):
    # Step 1: Scan document before embedding
    scan = requests.post(
        "https://api.aegis.security/api/v1/rag/scan",
        json={"document_id": doc_id, "text": text},
        headers={"x-api-key": "YOUR_KEY"}
    ).json()
    
    if not scan["safe_to_embed"]:
        print(f"Document {doc_id} rejected: {scan['risk_score']} risk")
        return False
    
    # Step 2: Embed (only if safe)
    vector = embed(text)
    store_in_vector_db(doc_id, vector)
    return True

def query_with_trace(query_id, query, chunks):
    # Trace the query
    trace = requests.post(
        "https://api.aegis.security/api/v1/rag/trace",
        json={"query_id": query_id, "query": query, "retrieved_chunks": chunks},
        headers={"x-api-key": "YOUR_KEY"}
    ).json()
    
    if trace["anomaly_score"] > 0.5:
        print(f"Query anomaly detected: {trace['explanation']}")
    
    return trace
```

---

## PHASE 3: DAY 2 — CONFIGURE PROTECTIONS

### Step 1: Set Prompt Defense Mode
```python
# Mode options:
# "monitor" — log only, no blocking (safe start)
# "flag" — flag suspicious, block malicious
# "block" — block both suspicious and malicious (production)

# Recommended: Start in "monitor" mode, review logs, then switch to "block"
```

### Step 2: Create Agent Policies
```yaml
# Example policy: Customer Support Agent
policies:
  - agent_id: "customer-support-agent"
    resources:
      - path: "filesystem:/reports/public/*"
        actions: ["read_file"]
        conditions:
          - key: "file.size_mb"
            operator: "lte"
            value: 10
      - path: "database:/customers/*"
        actions: ["query_database"]
        conditions:
          - key: "auth.user_id"
            operator: "eq"
            value: "{session.user_id}"
    default_action: "deny"
```

### Step 3: Set Up Alerting
```python
# Configure Slack webhook
requests.post(
    "https://api.aegis.security/api/v1/alert/config",
    json={"slack_webhook": "https://hooks.slack.com/services/..."},
    headers={"x-api-key": "YOUR_KEY"}
)

# Critical alerts: Slack + email
# High alerts: Slack only
# Medium alerts: Dashboard only
```

---

## PHASE 4: DAY 3 — ENABLE ADVANCED FEATURES

### Turn on Supply Chain Scanning
```bash
# Scan your existing models
aegis scan model --path ./models/llama.pt

# Scan your requirements
aegis scan requirements --file requirements.txt

# Continuous monitoring
aegis monitor registry --source huggingface
```

### Enable Vector Store Encryption
```python
# Encrypt existing vectors
encrypted = aegis.encrypt_vector([0.1, 0.2, 0.3])
# Store encrypted, decrypt on read
decrypted = aegis.decrypt_vector(encrypted)
```

### Configure Extraction Defense
```python
# Set watermarking level
aegis.configure_extraction_defense(
    watermark_rate=0.15,  # 15% of responses watermarked
    perturbation_scale=0.02,  # 2% noise on numerical values
    auto_block=True  # Block sessions with risk score > 0.9
)
```

---

## PHASE 5: DAY 4 — REVIEW & OPTIMIZE

### Review Audit Logs
```bash
# Get today's audit log
curl https://api.aegis.security/api/v1/audit?module=all&from=today

# Dashboard shows:
# - Total prompts analyzed
# - Blocked vs allowed
# - Top attack types
# - Module health
# - Risk trends
```

### Run Self-Protection Check
```bash
curl -X POST https://api.aegis.security/api/v1/self-protection/check
# Returns: {"status": "secure", "overall_score": 0.0, ...}
```

### Key Metrics to Monitor
| Metric | Healthy Range | Action If Outside |
|---|---|---|
| Prompt defense latency | <15ms | Scale gateway |
| Block rate | 1-5% of traffic | Review thresholds |
| False positive rate | <0.1% | Relax signatures |
| Agent auth latency | <5ms | Scale policy engine |
| Supply chain findings | 0 critical | Update dependencies |
| Self-protection score | 0.0 | Run integrity check |
| API uptime | 99.9%+ | Check infrastructure |

---

## CLIENT SUCCESS CHECKLIST

### Day 1
- [ ] Account created / Docker deployed
- [ ] API key configured
- [ ] First test prompt analyzed
- [ ] Dashboard accessible
- [ ] LLM integration done

### Day 2
- [ ] Prompt defense mode set (start with monitor)
- [ ] Agent policies created (if using agents)
- [ ] MCP gateway configured (if using MCP)
- [ ] Alerting configured (Slack/email)
- [ ] Team members invited

### Day 3
- [ ] RAG scanning enabled (if using RAG)
- [ ] Supply chain audit run
- [ ] Vector encryption configured
- [ ] Extraction defense enabled
- [ ] Custom attack signatures added

### Day 4
- [ ] Audit logs reviewed
- [ ] Thresholds tuned
- [ ] False positives addressed
- [ ] Compliance reporting set up
- [ ] Self-protection check passed

### Ongoing
- [ ] Weekly audit log review
- [ ] Monthly supply chain scan
- [ ] Quarterly policy review
- [ ] Annual penetration test
- [ ] Continuous monitoring active