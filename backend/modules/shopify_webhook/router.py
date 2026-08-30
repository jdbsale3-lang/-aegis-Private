# AEGIS Module 10: Shopify Webhook Receiver - API Router
# Stdlib-only Shopify webhook handler (HMAC-SHA256 hex signature verification)
# with idempotent event processing (claim-by-webhook-id).
# All IP belongs to JDB Sales.
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from modules.webhook_common.store import claim, init_store, count_processed

logger = logging.getLogger("aegis-shopify-webhook")

router = APIRouter(prefix="/shopify", tags=["shopify"])

_EVENT_LOG = Path(os.environ.get("AEGIS_SHOPIFY_EVENT_LOG", "/opt/aegis/data/shopify-events.jsonl"))

# Topics we act on. Everything else is logged but ignored (200 = acknowledged).
HANDLED_TOPICS = {
    "orders/create",
    "orders/paid",
    "orders/fulfilled",
    "orders/cancelled",
    "refunds/create",
    "products/create",
    "products/update",
    "customers/create",
    "customers/update",
    "app/uninstalled",
    "app/scopes_update",
    "checkouts/paid",
    "themes/publish",
}


def _client_secret() -> str | None:
    """Shopify app client secret (HMAC key) from env only."""
    return os.environ.get("SHOPIFY_CLIENT_SECRET")


def _verify_hmac(payload: bytes, header_value: str, secret: str) -> bool:
    """Shopify HMAC: Base64(HMAC-SHA256(secret, raw_body)) in X-Shopify-Hmac-Sha256."""
    if not header_value:
        return False
    import base64
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode()
    return hmac.compare_digest(expected, header_value.strip())


def _log_event(topic: str, webhook_id: str, shop: str, summary: dict) -> dict:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "webhook_id": webhook_id,
        "topic": topic,
        "shop": shop,
        "object": summary,
    }
    try:
        _EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _EVENT_LOG.open("a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.error("shopify event log write failed: %s", exc)
    return record


def _apply_action(record: dict) -> str:
    """Business action for handled topics (runs ONCE per webhook id)."""
    topic = record["topic"]
    obj = record["object"]
    if topic == "orders/paid":
        msg = f"SHOPIFY ORDER PAID {obj.get('order_number')} total={obj.get('total_price')} {obj.get('currency')}"
        logger.info("SHOPIFY: %s", msg)
        return msg
    if topic == "orders/create":
        msg = f"SHOPIFY ORDER CREATED {obj.get('order_number')} total={obj.get('total_price')} {obj.get('currency')}"
        logger.info("SHOPIFY: %s", msg)
        return msg
    if topic == "refunds/create":
        msg = f"SHOPIFY REFUND {obj.get('order_id')} amount={obj.get('amount')} {obj.get('currency')}"
        logger.info("SHOPIFY: %s", msg)
        return msg
    if topic == "app/uninstalled":
        msg = f"SHOPIFY APP UNINSTALLED {record.get('shop')} — deactivate/cleanup required"
        logger.warning("SHOPIFY: %s", msg)
        return msg
    return "logged-only"


@router.post("/webhook")
async def shopify_webhook(request: Request):
    """Shopify webhook receiver. Verify HMAC -> log -> claim idempotency -> action once."""
    secret = _client_secret()
    if not secret:
        logger.error("SHOPIFY_CLIENT_SECRET not set - rejecting webhook")
        return JSONResponse(status_code=500, content={"error": "webhook not configured"})

    payload = await request.body()
    hmac_header = request.headers.get("x-shopify-hmac-sha256", "")

    if not _verify_hmac(payload, hmac_header, secret):
        logger.warning("Shopify webhook HMAC verification FAILED")
        return JSONResponse(status_code=400, content={"error": "invalid signature"})

    topic = request.headers.get("x-shopify-topic", "unknown")
    shop = request.headers.get("x-shopify-shop-domain", "")
    webhook_id = request.headers.get("x-shopify-webhook-id", "")
    if not webhook_id:
        # Fallback id for very old clients: hash of topic+body so retries still dedupe.
        webhook_id = "derived_" + hashlib.sha256(payload).hexdigest()[:32]

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})

    summary = {"id": data.get("id"), "order_number": data.get("order_number"), "total_price": data.get("total_price"), "currency": data.get("currency"), "order_id": data.get("order_id"), "amount": data.get("amount")}
    record = _log_event(topic, webhook_id, shop, summary)

    # Idempotency: claim by webhook id BEFORE the action. First delivery -> True.
    claimed = claim(webhook_id, kind=f"shopify:{topic}")
    if not claimed:
        logger.info("SHOPIFY: duplicate delivery skipped (webhook_id=%s)", webhook_id)
        record["_action"] = "duplicate-skipped"
    else:
        record["_action"] = _apply_action(record)

    return Response(status_code=200, content="ok")  # ack in <5s (Shopify requirement)


@router.get("/webhook/status")
async def webhook_status():
    """Operational status (API-key gated)."""
    secret_set = bool(_client_secret())
    recent = []
    try:
        if _EVENT_LOG.exists():
            lines = _EVENT_LOG.read_text().strip().splitlines()
            recent = [json.loads(l) for l in lines[-5:]]
    except Exception:
        pass
    return {"configured": secret_set, "event_log": str(_EVENT_LOG), "recent_events": recent, "processed_count": count_processed()}


@router.get("/webhook/health")
async def webhook_health():
    """Public PII-free health probe (uptime monitors)."""
    return {
        "status": "ok" if _client_secret() else "unconfigured",
        "service": "aegis-shopify-webhook",
        "configured": bool(_client_secret()),
        "event_log_size": _EVENT_LOG.stat().st_size if _EVENT_LOG.exists() else 0,
    }


@router.get("/webhook/events")
async def list_events(limit: int = 20):
    """Recent received events (API-key gated)."""
    events = []
    try:
        if _EVENT_LOG.exists():
            lines = _EVENT_LOG.read_text().strip().splitlines()
            events = [json.loads(l) for l in lines[-limit:]]
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return {"events": events, "count": len(events)}