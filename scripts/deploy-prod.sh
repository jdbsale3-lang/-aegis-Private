#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# AEGIS AI Security — PRODUCTION DEPLOY (systemd + venv path, DigitalOcean)
# Host: aegis-api (178.62.46.133) · Ubuntu 24.04 · nginx -> systemd aegis-api
# Usage (as root or with sudo):
#   ./deploy.sh            # deploy latest main
#   ./deploy.sh --verify   # verify-only (no changes)
#   ./deploy.sh --rollback # restore pre-deploy snapshot
# All IP belongs to JDB Sales.
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

APP_DIR="/opt/aegis"
BACKEND="$APP_DIR/backend"
SERVICE="aegis-api.service"
REPO="https://github.com/jdbsale3-lang/-aegis-Private.git"
SNAP="$BACKEND.pre-deploy-$(date +%Y%m%d-%H%M%S)"
KEY_FILE="$APP_DIR/data/api_keys.json"

log()  { echo -e "\e[36m[AEGIS-DEPLOY]\e[0m $*"; }
fail() { echo -e "\e[31m[AEGIS-DEPLOY] FAIL\e[0m $*"; exit 1; }

# 1) checks
log "Preflight: service=$SERVICE app=$APP_DIR"
[ -d "$BACKEND" ] || fail "backend dir missing: $BACKEND"
command -v git systemctl >/dev/null || fail "git/systemctl missing"

# 2) verify-only
if [ "${1:-}" = "--verify" ]; then
  log "VERIFY MODE:"
  systemctl is-active "$SERVICE" || fail "service not active"
  curl -sf http://127.0.0.1:8000/health >/dev/null && log "  local health OK" || fail "local health failed"
  [ -f "$KEY_FILE" ] && log "  api_keys.json present ($(wc -l <"$KEY_FILE") lines)"
  cd "$BACKEND" && ./venv/bin/python -m py_compile api_server.py core/security.py modules/supply_chain/scanner.py modules/prompt_defense/classifier.py && log "  compile OK"
  log "  all good."
  exit 0
fi

# 3) rollback
if [ "${1:-}" = "--rollback" ]; then
  latest=$(ls -dt "$BACKEND".pre-deploy-* 2>/dev/null | head -1)
  [ -n "$latest" ] || fail "no snapshot found"
  rm -rf "$BACKEND" && cp -a "$latest" "$BACKEND" && chown -R aegis:aegis "$BACKEND"
  systemctl restart "$SERVICE" && sleep 3 && systemctl is-active "$SERVICE" && log "ROLLED BACK from $latest"
  exit 0
fi

# 4) snapshot current state (safety)
log "Snapshot: $SNAP"
[ -d "$BACKEND" ] && cp -a "$BACKEND" "$SNAP" || true

# 5) pull latest code (repo clone at /opt/aegis/repo, or fetch into temp and copy backend)
log "Fetching latest main"
mkdir -p "$APP_DIR/repo"
if [ -d "$APP_DIR/repo/.git" ]; then
  cd "$APP_DIR/repo" && git fetch origin main && git checkout -q origin/main -- .
else
  git clone -q --depth 1 --branch main "$REPO" "$APP_DIR/repo" || fail "clone failed"
fi

# 6) copy backend code in place (keep venv + data + PROD-ONLY entrypoint)
log "Copying backend code"
# PROD entrypoint (auth/register/quota/rate-headers) lives OUTSIDE the repo tree
# at /opt/aegis/api_server.prod.py - deploy restores it over the repo copy (which has no auth).
cp -a "$APP_DIR/repo/backend/." "$BACKEND/" || true
if [ -f "$APP_DIR/api_server.prod.py" ]; then
  cp -a "$APP_DIR/api_server.prod.py" "$BACKEND/api_server.py"
  log "Restored production api_server.py (auth/register/quota/rate-headers)"
else
  log "WARN: $APP_DIR/api_server.prod.py missing - auth entrypoint NOT restored!"
fi
chown -R aegis:aegis "$BACKEND"

# 7) verify + restart
cd "$BACKEND"
./venv/bin/python -m py_compile api_server.py core/security.py modules/supply_chain/scanner.py modules/prompt_defense/classifier.py || fail "compile failed"
log "Restarting $SERVICE"
systemctl restart "$SERVICE"
sleep 4
systemctl is-active "$SERVICE" || fail "service failed to start"

# 8) post-deploy acceptance (local origin)
curl -sf http://127.0.0.1:8000/health >/dev/null && log "health OK" || fail "health check failed"

log "DEPLOY COMPLETE. Public verify:"
curl -s -o /dev/null -w "  https://apiaegissecurity.tech/health -> %{http_code}\n" https://apiaegissecurity.tech/health || true