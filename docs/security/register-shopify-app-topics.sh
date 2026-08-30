#!/usr/bin/env bash
# ZEUS — Register the 3 remaining Shopify webhook topics (app-level).
# Runs ONLY after zeus-ai-digital-app-1 is INSTALLED on the store and a valid
# shpat_ Admin API token exists. Fire with: SHOP_TOKEN=shpat_XXX ./register-shopify-app-topics.sh
# All IP belongs to JDB Sales.
set -euo pipefail

STORE="${1:-xegrdn-7v.myshopify.com}"
ADDRESS="https://apiaegissecurity.tech/shopify/webhook"
API="https://${STORE}/admin/api/2024-10/webhooks.json"

: "${SHOP_TOKEN:?Set SHOP_TOKEN to the shpat_ Admin API access token (created when the app is installed)}"

echo "== Verifying token against $STORE =="
CODE=$(curl -s -o /tmp/shop_check.json -w "%{http_code}" "$API" -H "X-Shopify-Access-Token: $SHOP_TOKEN")
if [ "$CODE" != "200" ]; then echo "AUTH FAILED (HTTP $CODE) — app not installed or token invalid."; head -c 200 /tmp/shop_check.json; exit 1; fi
echo "Token OK — app is installed."

echo "== Existing webhooks (app-level check) =="
curl -s "$API" -H "X-Shopify-Access-Token: $SHOP_TOKEN" | python3 -c "import json,sys; ws=json.load(sys.stdin).get('webhooks',[]); [print(' ', w['topic'], '->', w['address']) for w in ws]"

echo "== Registering 3 app-level topics =="
for T in "app/uninstalled" "app/scopes_update" "checkouts/paid"; do
  RESP=$(curl -s -o /tmp/wh_one.json -w "%{http_code}" -X POST "$API" \
    -H "X-Shopify-Access-Token: $SHOP_TOKEN" -H "Content-Type: application/json" \
    -d "{\"webhook\":{\"topic\":\"$T\",\"address\":\"$ADDRESS\",\"format\":\"json\"}}")
  if [ "$RESP" = "201" ]; then
    echo "  CREATE $T -> OK (id $(python3 -c "import json;print(json.load(open('/tmp/wh_one.json')).get('webhook',{}).get('id'))"))"
  else
    echo "  CREATE $T -> HTTP $RESP: $(head -c 200 /tmp/wh_one.json)"
  fi
  sleep 0.6
done

echo "== Verify: full webhook list =="
curl -s "$API" -H "X-Shopify-Access-Token: $SHOP_TOKEN" | python3 -c "
import json,sys
ws=[w for w in json.load(sys.stdin).get('webhooks',[])]
print('total webhooks:', len(ws))
for w in ws: print(' ', w['id'], w['topic'], '->', w['address'])
"