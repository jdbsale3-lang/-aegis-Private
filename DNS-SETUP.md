# AEGIS API — DNS & SSL Setup Guide

## Problem
The domain `api.aegis.security` is registered at **Porkbun** and currently points to a parking page (`pixie.porkbun.com`), causing an SSL error when accessed.

## Fix: Update DNS Records at Porkbun

### Step 1: Log into Porkbun
1. Go to https://porkbun.com
2. Log in with your account credentials
3. Click "Domains" in the top menu
4. Click on `aegis.security`

### Step 2: Add DNS Records
Click "DNS Records" then add:

| Type | Host | Answer | TTL |
|---|---|---|---|
| **A** | `api` | `YOUR_SERVER_IP_ADDRESS` | 600 |
| **CNAME** | `www.api` | `api.aegis.security` | 600 |

Replace `YOUR_SERVER_IP_ADDRESS` with the IP of the server where AEGIS is deployed.

### Step 3: Deploy AEGIS on Your Server
```bash
# On your server (Ubuntu/Debian):
apt update && apt install -y python3 python3-pip nginx certbot

# Clone and deploy
git clone https://github.com/zeus-ai/aegis
cd aegis/backend
pip install -r requirements.txt

# Start API server (use systemd for persistence)
python api_server.py --port 8000
```

### Step 4: Set Up SSL with Let's Encrypt
```bash
# Configure nginx to proxy to the API
cat > /etc/nginx/sites-available/aegis-api << 'EOF'
server {
    listen 80;
    server_name api.aegis.security;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Enable and get SSL
ln -s /etc/nginx/sites-available/aegis-api /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
certbot --nginx -d api.aegis.security
```

### Step 5: Verify
```bash
curl https://api.aegis.security/health
# → {"status": "healthy", "service": "AEGIS", "version": "1.0.0"}

curl https://api.aegis.security/api/v1/prompt/analyze \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello world", "mode": "monitor"}'
# → {"verdict": "safe", "latency_ms": 3.4}
```

## Local Development (No Domain Needed)
```bash
cd aegis-mvp/backend
python api_server.py
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

## Live Sites
- **Landing Page:** https://aegis-security.higgsfield.app
- **API Docs:** https://aegis-api-docs.higgsfield.app
- **API (when configured):** https://api.aegis.security