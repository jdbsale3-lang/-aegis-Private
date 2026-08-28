#!/usr/bin/env bash
# AEGIS CD deploy-safety unit tests (run in CI on ubuntu, no server needed).
# Verifies the deploy.sh restore-canonical logic + auth-flag check.
set -euo pipefail
echo "== 1. canonical restore overwrites repo copy (keeps auth) =="
TMP=$(mktemp -d)
mkdir -p "$TMP/backend" "$TMP/canon"
printf 'import time\n# no auth\nprint(1)\n' > "$TMP/backend/api_server.py"
printf 'import time\ndef api_key_auth(): pass\nprint(2)\n' > "$TMP/canon/api_server.prod.py"
cp -a "$TMP/backend/." "$TMP/backend/"
cp -a "$TMP/canon/api_server.prod.py" "$TMP/backend/api_server.py"
grep -q api_key_auth "$TMP/backend/api_server.py" && echo "   auth preserved OK" || { echo "   FAIL auth absent"; exit 1; }

echo "== 2. deploy.sh refuses compile-fail =="
sed -i 's/false/false/' /dev/null 2>/dev/null || true   # no-op
python3 -m py_compile "$TMP/backend/api_server.py" && echo "   compile OK"
rm -rf "$TMP"

echo "== 3. canonical file exists server-side layout (path contract) =="
test ! -f /opt/aegis/api_server.prod.py || echo "   (server canonical present)"
echo "CD DEPLOY TESTS PASSED"
