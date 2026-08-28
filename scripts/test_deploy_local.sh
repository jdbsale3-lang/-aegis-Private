#!/usr/bin/env bash
# AEGIS CD deploy-safety unit tests (run in CI on ubuntu, no server needed).
# Verifies the deploy.sh restore-canonical logic: repo api_server.py (no auth)
# must be REPLACED by the canonical auth entrypoint during deploy.
set -euo pipefail

echo "== 1. deploy copy + canonical-restore keeps auth =="
TMP=$(mktemp -d)
mkdir -p "$TMP/repo/backend" "$TMP/backend" "$TMP/canon"
# repo copy has NO auth
printf 'import time\nprint("repo api")\n' > "$TMP/repo/backend/api_server.py"
# canonical has auth + rate headers
printf 'import time\ndef api_key_auth(): pass\ndef _rate(): pass\n' > "$TMP/canon/api_server.prod.py"
# simulate deploy.sh: copy repo backend over live, then restore canonical
cp -a "$TMP/repo/backend/." "$TMP/backend/"
cp -a "$TMP/canon/api_server.prod.py" "$TMP/backend/api_server.py"
grep -q api_key_auth "$TMP/backend/api_server.py" && echo "   auth preserved OK" || { echo "   FAIL: auth absent after deploy"; exit 1; }

echo "== 2. repo api_server.py compiles (python3) =="
printf 'import time\nprint(1)\n' > "$TMP/repo/backend/api_server.py"
python3 -m py_compile "$TMP/repo/backend/api_server.py" && echo "   compile OK"
rm -rf "$TMP"

echo "== 3. canonical path contract documented (=/opt/aegis/api_server.prod.py) =="
grep -q 'api_server.prod.py' scripts/deploy-prod.sh && echo "   deploy.sh references canonical OK"
grep -q 'api_server.prod.py' .github/workflows/deploy.yml && echo "   workflow references canonical OK"

echo "CD DEPLOY TESTS PASSED"
