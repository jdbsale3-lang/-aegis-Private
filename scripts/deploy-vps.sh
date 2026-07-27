#!/bin/bash
# AEGIS API - VPS Deployment Script
# Run this on a fresh Ubuntu 22.04+ server as root
# Usage: curl -sL https://raw.githubusercontent.com/zeus-ai/aegis/main/scripts/deploy-vps.sh | bash

set -euo pipefail

echo "========================================="
echo "  AEGIS AI Security Platform - VPS Deploy"
echo "========================================="

# Update system
apt-get update && apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv nginx certbot git curl

# Clone AEGIS
cd /opt
git clone https://github.com/zeus-ai/aegis
cd aegis/backend

# Create venv and install deps
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate

# Create systemd service
cat > /etc/systemd/system/aegis-api.service << 'SERVICEEOF'
[Unit]
Description=AEGIS AI Security API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aegis/backend
ExecStart=/opt/aegis/backend/venv/bin/python /opt/aegis/backend/api_server.py
Restart=always
RestartSec=5
Environment=PORT=8000

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable aegis-api
systemctl start aegis-api

# Verify API is running
sleep 3
curl -s http://localhost:8000/health || { echo "API failed to start"; exit 1; }

# Configure nginx
cat > /etc/nginx/sites-available/aegis-api << 'NGINXEOF'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }
}
NGINXEOF

ln -sf /etc/nginx/sites-available/aegis-api /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# Get SSL (if domain is configured)
DOMAIN=${AEGIS_DOMAIN:-""}
if [ -n "$DOMAIN" ]; then
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN" || true
fi

# Run tests
cd /opt/aegis/backend
source venv/bin/activate
pip install pytest
python -m pytest tests/ -v

echo ""
echo "========================================="
echo "  AEGIS API DEPLOYMENT COMPLETE!"
echo "========================================="
echo "  Local: http://localhost:8000"
echo "  Docs:  http://localhost:8000/docs"
echo "  Health: curl http://localhost:8000/health"
echo ""
echo "  To set up a domain:"
echo "  1. Point your DNS A record to this server's IP"
echo "  2. Run: certbot --nginx -d your-domain.com"
echo "========================================="