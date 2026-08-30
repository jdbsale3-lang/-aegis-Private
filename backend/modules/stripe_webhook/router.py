# AEGIS Module 9: Stripe Webhook Receiver - API Router
# Stdlib-only Stripe webhook handler (HMAC-SHA256 signature verification).
# All IP belongs to JDB Sales.
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request, Response, status
from fastapi.responses import JSONResponse

from modules.webhook_common.store import claim, init_store, count_processed

logger = logging.getLogger("aegis-stripe-webhook")

router = APIRouter(prefix="/stripe", tags=["stripe"])

# Event log -> /opt/aegis/stripe-events.jsonl (append-only, no DB needed)
_EVENT_LOG = Path(os.environ.get("AEGIS_STRIPE_EVENT_LOG", "/opt/aegis/data/stripe-events.jsonl"))

# Event types we act on. Everything else is logged but ignored (return 200 so
# Stripe stops retrying).
HANDLED_EVENTS = {
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "invoice.paid",
    "invoice.payment_succeeded",
    "invoice.payment_failed",
    "invoice.finalized",
    "payment_intent.succeeded",
    "payment_intent.payment_failed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "customer.created",
    "customer.deleted",
}


def _webhook_secret() -> str | None:
    """Secret comes from the environment only (set via systemd drop-in)."""
    return os.environ.get("STRIPE_WEBHOOK_SECRET")


def _verify_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify Stripe's standard 't=...,v1=...' HMAC-SHA256 signature."""
    if not sig_header:
        return False
    parts = {}
    for item in sig_header.split(","):
        kv = item.split("=", 1)
        if len(kv) == 2:
            parts[kv[0]] = kv[1]
    t = parts.get("t")
    v1 = parts.get("v1")
    if not t or not v1:
        return False
    try:
        # Reject timestamps older than 5 minutes (replay protection)
        if abs(time.time() - float(t)) > 300:
            logger.warning("Stripe webhook timestamp outside 5min window (possible replay)")
            return False
    except ValueError:
        return False
    signed_payload = f"{t}.{payload.decode()}".encode()
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)


def _log_event(event: dict) -> dict:
    """Append event summary to the JSONL log; return the stored record."""
    ev_type = event.get("type", "unknown")
    data = event.get("data", {}).get("object", {})
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "id": event.get("id"),
        "type": ev_type,
        "api_version": event.get("api_version"),
        "object": {
            "id": data.get("id"),
            "status": data.get("status"),
            "amount": data.get("amount"),
            "currency": data.get("currency"),
            "customer": data.get("customer"),
            "email": data.get("customer_details", {}).get("email") if isinstance(data.get("customer_details"), dict) else None,
        },
    }
    try:
        _EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _EVENT_LOG.open("a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:  # never fail the webhook because logging failed
        logger.error("stripe event log write failed: %s", exc)
    return record


def _apply_action(record: dict) -> str:
    """Business action for handled events. Logs the action; side effects hook here."""
    ev_type = record["type"]
    obj = record["object"]
    if ev_type == "invoice.payment_succeeded" or ev_type == "invoice.paid":
        msg = f"PAYMENT RECEIVED {obj.get('currency','')} {obj.get('amount',0)/100} (invoice {obj.get('id')}, customer {obj.get('customer')})"
        logger.info("STRIPE: %s", msg)
        return msg
    if ev_type == "checkout.session.completed":
        msg = f"CHECKOUT COMPLETED {obj.get('currency','')} {obj.get('amount_total',0)/100} (session {obj.get('id')}, email {obj.get('email')})"
        logger.info("STRIPE: %s", msg)
        return msg
    if ev_type == "payment_intent.succeeded":
        msg = f"PAYMENT INTENT SUCCEEDED {obj.get('id')}"
        logger.info("STRIPE: %s", msg)
        return msg
    if ev_type.startswith("customer.subscription"):
        msg = f"SUBSCRIPTION {ev_type.split('.')[-1].upper()} {obj.get('id')} status={obj.get('status')}"
        logger.info("STRIPE: %s", msg)
        return msg
    if ev_type == "invoice.payment_failed":
        msg = f"PAYMENT FAILED (invoice {obj.get('id')}, customer {obj.get('customer')})"
        logger.warning("STRIPE: %s", msg)
        return msg
    return "logged-only"


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Stripe webhook receiver. Verifies signature, logs, then applies business action."""
    secret = _webhook_secret()
    if not secret:
        logger.error("STRIPE_WEBHOOK_SECRET not set - rejecting webhook")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"error": "webhook not configured"})

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if not _verify_signature(payload, sig_header, secret):
        logger.warning("Stripe webhook signature verification FAILED")
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid signature"})

    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid JSON"})

    record = _log_event(event)
    # Idempotency: claim by event.id BEFORE any side effect. First delivery -> True.
    claimed = claim(event.get("id", ""), kind=f"stripe:{event.get('type', 'unknown')}")
    if not claimed:
        # Duplicate retry/redelivery — acknowledge (200) but do NOT re-run actions.
        record["_action"] = "duplicate-skipped"
        logger.info("STRIPE: duplicate delivery skipped (%s)", event.get("id"))
        return Response(status_code=status.HTTP_200_OK, content="ok")

    record["_action"] = _apply_action(record)

    # Handled events return 200 immediately (Stripe stops retrying).
    # Unknown events also return 200, just logged.
    return Response(status_code=status.HTTP_200_OK, content="ok")


@router.get("/webhook/status")
async def webhook_status():
    """Operational status: secret configured? last events?? (API-key gated)"""
    secret_set = bool(_webhook_secret())
    recent = []
    try:
        if _EVENT_LOG.exists():
            lines = _EVENT_LOG.read_text().strip().splitlines()
            recent = [json.loads(l) for l in lines[-5:]]
    except Exception:
        pass
    return {"configured": secret_set, "event_log": str(_EVENT_LOG), "recent_events": recent}


@router.get("/webhook/health")
async def webhook_health():
    """Public health probe (NO PII, NO event data) — safe for uptime monitors."""
    return {
        "status": "ok" if _webhook_secret() else "unconfigured",
        "service": "aegis-stripe-webhook",
        "configured": bool(_webhook_secret()),
        "event_log_size": _EVENT_LOG.stat().st_size if _EVENT_LOG.exists() else 0,
    }


@router.get("/webhook/events")
async def list_events(limit: int = 20):
    """List the most recent received Stripe events (operational visibility)."""
    events = []
    try:
        if _EVENT_LOG.exists():
            lines = _EVENT_LOG.read_text().strip().splitlines()
            events = [json.loads(l) for l in lines[-limit:]]
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return {"events": events, "count": len(events)}