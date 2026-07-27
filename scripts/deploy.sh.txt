#!/bin/bash
# AEGIS - Production Deployment Script
# Usage: ./deploy.sh [environment]
# Requires: docker, docker-compose, openssl

set -euo pipefail

ENV=${1:-production}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOY_DIR="$PROJECT_DIR/deploy/docker"

echo "========================================="
echo "  AEGIS AI Security Platform - Deploy"
echo "  Environment: $ENV"
echo "========================================="

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl is required"; exit 1; }

# Load environment
if [ -f "$PROJECT_DIR/.env.production" ]; then
    set -a
    source "$PROJECT_DIR/.env.production"
    set +a
    echo "Loaded environment from .env.production"
else
    echo "WARNING: .env.production not found. Using existing environment variables."
    echo "Create .env.production with required variables:"
    echo "  AEGIS_DB_PASSWORD"
    echo "  AEGIS_REDIS_PASSWORD"
    echo "  AEGIS_JWT_SECRET"
    echo "  AEGIS_API_KEY"
    echo "  AEGIS_CORS_ORIGINS"
fi

# Validate required variables
: "${AEGIS_DB_PASSWORD:?Required}"
: "${AEGIS_REDIS_PASSWORD:?Required}"
: "${AEGIS_JWT_SECRET:?Required}"
: "${AEGIS_API_KEY:?Required}"

# Generate SSL certs if they don't exist
if [ ! -f "$DEPLOY_DIR/ssl/cert.pem" ]; then
    echo "Generating self-signed SSL certificates..."
    mkdir -p "$DEPLOY_DIR/ssl"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$DEPLOY_DIR/ssl/key.pem" \
        -out "$DEPLOY_DIR/ssl/cert.pem" \
        -subj "/C=US/ST=State/L=City/O=AEGIS/CN=api.aegis.security"
    echo "SSL certificates generated"
fi

# Create required directories
mkdir -p "$DEPLOY_DIR/grafana-dashboards"

# Run AEGIS self-protection check before deploy
echo "Running pre-deploy self-protection check..."
cd "$PROJECT_DIR/backend"
python3 -c "
import sys; sys.path.insert(0, '.')
from modules.self_protection.watcher import AEGISSelfProtection
w = AEGISSelfProtection(workspace_path='.')
r = w.run_full_check()
print(f'Status: {r.status} (score: {r.overall_score})')
if r.status == 'compromised':
    print('ERROR: Self-protection check failed!')
    sys.exit(1)
" || { echo "Self-protection check failed. Aborting deploy."; exit 1; }

# Run tests
echo "Running test suite..."
cd "$PROJECT_DIR/backend"
python3 -m pytest tests/ -v --tb=short || { echo "Tests failed. Aborting deploy."; exit 1; }

# Pull latest images
echo "Pulling Docker images..."
docker compose -f "$DEPLOY_DIR/docker-compose.prod.yml" pull

# Deploy
echo "Deploying AEGIS stack..."
docker compose -f "$DEPLOY_DIR/docker-compose.prod.yml" up -d --build

# Wait for health checks
echo "Waiting for services to be healthy..."
sleep 10

# Verify deployment
echo "Verifying deployment..."
MAX_RETRIES=10
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
        echo "Backend is healthy!"
        break
    fi
    RETRY=$((RETRY + 1))
    echo "Waiting... (attempt $RETRY/$MAX_RETRIES)"
    sleep 3
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "ERROR: Backend failed to start. Check logs:"
    docker compose -f "$DEPLOY_DIR/docker-compose.prod.yml" logs backend
    exit 1
fi

# Verify MCP gateway
if curl -sf http://localhost:8443/health > /dev/null 2>&1; then
    echo "MCP Gateway is healthy!"
else
    echo "WARNING: MCP Gateway health check failed"
fi

# Run AEGIS self-protection check post-deploy
echo "Running post-deploy self-protection check..."
cd "$PROJECT_DIR/backend"
python3 -c "
import sys; sys.path.insert(0, '.')
from modules.self_protection.watcher import AEGISSelfProtection
w = AEGISSelfProtection(workspace_path='.')
r = w.run_full_check()
print(f'Post-deploy status: {r.status} (score: {r.overall_score})')
"

echo ""
echo "========================================="
echo "  AEGIS Deployment Complete!"
echo "  API: https://api.aegis.security"
echo "  Health: http://localhost:8000/health"
echo "  Grafana: http://localhost:3000"
echo "========================================="
echo ""
echo "Next steps:"
echo "  1. Configure SSL certificates for your domain"
echo "  2. Set up DNS records for api.aegis.security"
echo "  3. Configure alerting webhook in .env.production"
echo "  4. Run 'docker compose logs -f' to monitor"