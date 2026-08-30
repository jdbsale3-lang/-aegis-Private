#!/usr/bin/env bash
# ZEUS — Register all 13 Shopify webhook topics to the AEGIS receiver.
# Run:  SHOP_TOKEN=shpat_XXX ./register-shopify-webhooks.sh [STORE_DOMAIN]
# Defaults to zeusai2026.myshopify.com. Requires a valid Admin API access token (shpat_…).
# All IP belongs to JDB Sales.
set -euo pipefail

STORE="${1:-zeusai2026.myshopify.com}"
ADDRESS="https://apiaegissecurity.tech/shopify/webhook"
API="https://${STORE}/admin/api/2024-10/webhooks.json"

: "${SHOP_TOKEN:?Set SHOP_TOKEN to the shpat_… Admin API access token}"

TOPICS=(
  "orders/create" "orders/paid" "orders/fulfilled" "orders/cancelled"
  "refunds/create" "products/create" "products/update"
  "customers/create" "customers/update"
  "app/uninstalled" "app/scopes_update" "checkouts/paid" "themes/publish"
)

echo "== Verifying token against $STORE =="
CODE=$(curl -s -o /tmp/shop_check.json -w "%{http_code}" "$API" -H "X-Shopify-Access-Token: $SHOP_TOKEN")
if [ "$CODE" != "200" ]; then
  echo "AUTH FAILED (HTTP $CODE) — check the token is the Admin API access token (shpat_…), not the client secret."
  cat /tmp/shop_check.json; exit 1
fi
echo "Token OK."

echo "== Existing webhooks =="
curl -s "$API" -H "X-Shopify-Access-Token: $SHOP_TOKEN" | python3 -c "import json,sys; [print(' ', w['topic'], '->', w['address']) for w in json.load(sys.stdin).get('webhooks',[])]"

echo "== Registering ${#TOPICS[@]} topics =="
for T in "${TOPICS[@]}"; do
  RESP=$(curl -s -o /tmp/wh_one.json -w "%{http_code}" -X POST "$API" \
    -H "X-Shopify-Access-Token: $SHOP_TOKEN" -H "Content-Type: application/json" \
    -d "{\"webhook\":{\"topic\":\"$T\",\"address\":\"$ADDRESS\",\"format\":\"json\"}}")
  if [ "$RESP" = "201" ]; then
    echo "  CREATE $T -> OK ($(python3 -c "import json;print(json.load(open('/tmp/wh_one.json')).get('webhook',{}).get('id'))"))"
  else
    echo "  CREATE $T -> HTTP $RESP: $(head -c 200 /tmp/wh_one.json)"
  fi
  sleep 0.6  # respect 2 req/s REST limit
done

echo "== Verify: all 13 registered =="
curl -s "$API" -H "X-Shopify-Access-Token: $SHOP_TOKEN" | python3 -c "
import json,sys
ws=[w for w in json.load(sys.stdin).get('webhooks',[])]
print('total webhooks:', len(ws))
for w in ws: print(' ', w['id'], w['topic'], '->', w['address'])
"