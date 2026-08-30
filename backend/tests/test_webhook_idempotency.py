"""
AEGIS webhook idempotency test suite.

Proves the at-least-once webhook contract for BOTH receivers (Stripe + Shopify):
  1. First delivery of an event  -> action runs once, event claimed
  2. Retry/redelivery of SAME id -> 200 acknowledged, action does NOT re-run
  3. Bad signature               -> 400 rejected, nothing claimed/acted
  4. Different events            -> each runs its action exactly once
  5. Store is durable across receivers (shared claim table)

Run from backend/:  venv/bin/python -m pytest tests/test_webhook_idempotency.py -v
All IP belongs to JDB Sales.
"""
import base64
import hashlib
import hmac
import json
import os
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# --- isolate all state before importing the routers -------------------------
TEST_DIR = "/tmp/aegis-webhook-tests"
os.makedirs(TEST_DIR, exist_ok=True)
os.environ["AEGIS_PROCESSED_DB"] = os.path.join(TEST_DIR, "processed.db")
os.environ["AEGIS_STRIPE_EVENT_LOG"] = os.path.join(TEST_DIR, "stripe.jsonl")
os.environ["AEGIS_SHOPIFY_EVENT_LOG"] = os.path.join(TEST_DIR, "shopify.jsonl")
os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test_secret_123"
os.environ["SHOPIFY_CLIENT_SECRET"] = "b22f9e4e6286836e699a5292232140c1"

from modules.webhook_common.store import claim, count_processed, init_store  # noqa: E402
from modules.stripe_webhook.router import router as stripe_router  # noqa: E402
from modules.shopify_webhook.router import router as shopify_router  # noqa: E402

# fresh store per run
for f in ("processed.db", "stripe.jsonl", "shopify.jsonl"):
    path = os.path.join(TEST_DIR, f)
    if os.path.exists(path):
        os.remove(path)

init_store()

app = FastAPI()
app.include_router(stripe_router)
app.include_router(shopify_router)
client = TestClient(app)


# --- helpers ----------------------------------------------------------------
def stripe_event(evt_id: str, evt_type: str, amount: int = 100) -> dict:
    return {
        "id": evt_id,
        "object": "event",
        "api_version": "2024-06-20",
        "created": int(time.time()),
        "type": evt_type,
        "data": {"object": {"id": f"in_{evt_id}", "status": "paid", "amount": amount, "currency": "gbp", "customer": "cus_test"}},
    }


def stripe_sign(payload: bytes, secret: str = "whsec_test_secret_123") -> str:
    t = str(int(time.time()))
    sig = hmac.new(secret.encode(), f"{t}.{payload.decode()}".encode(), hashlib.sha256).hexdigest()
    return f"t={t},v1={sig}"


def deliver_stripe(evt_id: str, evt_type: str = "invoice.payment_succeeded", amount: int = 100, secret: str | None = None):
    evt = stripe_event(evt_id, evt_type, amount)
    body = json.dumps(evt).encode()
    headers = {"Content-Type": "application/json"}
    if secret is None:
        headers["Stripe-Signature"] = stripe_sign(body)
    else:
        headers["Stripe-Signature"] = stripe_sign(body, secret)
    return client.post("/stripe/webhook", content=body, headers=headers)


def shopify_sign(payload: bytes, secret: str = "b22f9e4e6286836e699a5292232140c1") -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def deliver_shopify(webhook_id: str, topic: str = "orders/paid", secret: str | None = None):
    body = json.dumps({"id": webhook_id, "order_number": 1001, "total_price": "129.00", "currency": "GBP"}).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Topic": topic,
        "X-Shopify-Shop-Domain": "test-store.myshopify.com",
        "X-Shopify-Webhook-Id": webhook_id,
        "X-Shopify-Api-Version": "2024-10",
        "X-Shopify-Hmac-Sha256": shopify_sign(body) if secret is None else shopify_sign(body, secret),
    }
    return client.post("/shopify/webhook", content=body, headers=headers)


# --- store unit tests -------------------------------------------------------
def test_claim_is_atomic_first_true_second_false():
    assert claim("unit_claim_1", kind="test") is True
    assert claim("unit_claim_1", kind="test") is False  # duplicate


def test_claim_missing_id_is_permissive():
    assert claim("") is True


# --- stripe receiver --------------------------------------------------------
def test_stripe_first_delivery_200_and_claimed():
    r = deliver_stripe("evt_stripe_001")
    assert r.status_code == 200
    assert r.text == "ok"
    assert count_processed(kind="stripe:invoice.payment_succeeded") >= 1


def test_stripe_duplicate_redelivery_200_but_no_double_action():
    count_before = count_processed(kind="stripe:invoice.payment_succeeded")
    # first delivery
    assert deliver_stripe("evt_stripe_dup_01").status_code == 200
    # Stripe retry/redelivery of the SAME event id
    r2 = deliver_stripe("evt_stripe_dup_01")
    assert r2.status_code == 200  # acknowledged — Stripe stops retrying
    r3 = deliver_stripe("evt_stripe_dup_01")
    assert r3.status_code == 200
    # claimed exactly once -> action ran once (not 3x)
    assert count_processed(kind="stripe:invoice.payment_succeeded") == count_before + 1


def test_stripe_different_events_each_process_once():
    c0 = count_processed(kind="stripe:invoice.paid")
    for i in range(3):
        deliver_stripe(f"evt_stripe_paid_{i}", evt_type="invoice.paid", amount=1000 * (i + 1))
        deliver_stripe(f"evt_stripe_paid_{i}", evt_type="invoice.paid", amount=1000 * (i + 1))  # dup
    assert count_processed(kind="stripe:invoice.paid") == c0 + 3


def test_stripe_bad_signature_rejected_and_not_claimed():
    evt_id = "evt_stripe_bad"
    r = deliver_stripe(evt_id, secret="whsec_WRONG")
    assert r.status_code == 400
    evt = stripe_event(evt_id, "invoice.payment_succeeded")
    body = json.dumps(evt).encode()
    r2 = client.post("/stripe/webhook", content=body, headers={"Content-Type": "application/json"})  # no signature
    assert r2.status_code == 400
    from modules.webhook_common.store import is_processed
    assert is_processed(evt_id) is False


def test_stripe_replay_window_rejects_old_timestamp():
    evt = stripe_event("evt_stripe_old", "invoice.payment_succeeded")
    body = json.dumps(evt).encode()
    t = str(int(time.time()) - 3600)  # 1 hour old -> outside 5-min window
    sig = hmac.new(b"whsec_test_secret_123", f"{t}.{body.decode()}".encode(), hashlib.sha256).hexdigest()
    r = client.post("/stripe/webhook", content=body, headers={"Content-Type": "application/json", "Stripe-Signature": f"t={t},v1={sig}"})
    assert r.status_code == 400


# --- shopify receiver -------------------------------------------------------
def test_shopify_first_delivery_200_action_once():
    assert deliver_shopify("wh_shopify_001").status_code == 200
    assert count_processed(kind="shopify:orders/paid") >= 1


def test_shopify_duplicate_retry_suppressed():
    wid = "wh_shopify_dup_01"
    c0 = count_processed(kind="shopify:orders/paid")
    for _ in range(3):
        assert deliver_shopify(wid).status_code == 200
    assert count_processed(kind="shopify:orders/paid") == c0 + 1


def test_shopify_bad_hmac_rejected_and_not_claimed():
    wid = "wh_shopify_bad"
    r = deliver_shopify(wid, secret="wrong_secret")
    assert r.status_code == 400
    from modules.webhook_common.store import is_processed
    assert is_processed(wid) is False


def test_shopify_derived_id_dedupes_when_header_missing():
    # no X-Shopify-Webhook-Id -> derived id from body hash: same body twice = same id
    body = json.dumps({"id": 1, "total_price": "10.00", "currency": "GBP"}).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Topic": "orders/create",
        "X-Shopify-Shop-Domain": "test-store.myshopify.com",
        "X-Shopify-Hmac-Sha256": shopify_sign(body),
    }
    assert client.post("/shopify/webhook", content=body, headers=headers).status_code == 200
    assert client.post("/shopify/webhook", content=body, headers=headers).status_code == 200
    assert count_processed(kind="shopify:orders/create") == 1


# --- health gating ----------------------------------------------------------
def test_health_endpoints_are_pii_free():
    rh = client.get("/stripe/webhook/health")
    assert rh.status_code == 200
    assert "recent_events" not in rh.json()
    sh = client.get("/shopify/webhook/health")
    assert sh.status_code == 200
    assert "recent_events" not in sh.json()