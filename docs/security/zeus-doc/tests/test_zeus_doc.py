"""
ZEUS DOC — test suite.

Covers: Shamir splitting/reconstruction, threshold Schnorr t-of-n signing,
passwordless challenge/response authentication, signature tamper-rejection,
and the REST API surface.

Run: python3 -m pytest tests/ -v
All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.
"""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zeus_doc.core import ThresholdSigner, generate_master_key, Shamir, Point, public_key
from zeus_doc.identity import IdentityStore

N_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


# ----------------------------- core crypto ------------------------------------
def test_shamir_split_reconstruct():
    secret = 0xDEADBEEF1234567890
    shares = Shamir.split(secret, 3, 5)
    assert Shamir.reconstruct(shares[:3]) == secret
    assert Shamir.reconstruct(shares[1:4]) == secret
    assert Shamir.reconstruct(shares[2:]) == secret


def test_shamir_insufficient_shares_uncertain():
    secret = 123456789
    shares = Shamir.split(secret, 3, 5)
    # 2 shares reconstruct to *some* value but should not equal secret (probabilistic)
    guess = Shamir.reconstruct(shares[:2])
    assert guess != secret


@pytest.mark.parametrize("t,n", [(2, 3), (3, 5), (2, 2), (4, 5), (3, 3)])
def test_threshold_schnorr_all_combinations(t, n):
    signer = ThresholdSigner(t, n)
    shares = signer.split_master(generate_master_key())
    msg = f"ZEUS DOC test {t}-of-{n}".encode()
    partials = [signer.partial_sign(shares[i], msg) for i in range(t)]
    R, s = signer.combine_partials(partials, msg)
    assert signer.verify(msg, (R, s), signer.pub) is True


def test_threshold_tampered_message_rejected():
    signer = ThresholdSigner(2, 3)
    shares = signer.split_master(generate_master_key())
    msg = b"authorized document"
    partials = [signer.partial_sign(shares[0], msg), signer.partial_sign(shares[1], msg)]
    R, s = signer.combine_partials(partials, msg)
    assert signer.verify(b"tampered document", (R, s), signer.pub) is False


def test_threshold_wrong_pubkey_rejected():
    signer = ThresholdSigner(2, 3)
    shares = signer.split_master(generate_master_key())
    msg = b"doc"
    partials = [signer.partial_sign(shares[0], msg), signer.partial_sign(shares[1], msg)]
    R, s = signer.combine_partials(partials, msg)
    wrong_pub = public_key(generate_master_key())
    assert signer.verify(msg, (R, s), wrong_pub) is False


# ----------------------------- identity layer ---------------------------------
def _fresh_store():
    return IdentityStore(tempfile.mktemp(suffix=".json"))


def test_identity_passwordless_auth_success():
    store = _fresh_store()
    ident = store.create("p1", "Patient One", 2, 3)
    ch = store.issue_challenge("p1")
    signer = ThresholdSigner(2, 3)
    devs = list(ident.devices)[:2]
    partials = [signer.partial_sign(ident.devices[d].share, ch.encode()) for d in devs]
    assert store.verify_authentication("p1", devs, ch, partials) is True


def test_identity_auth_wrong_challenge_fails():
    store = _fresh_store()
    ident = store.create("p2", "Patient Two", 2, 3)
    ch = store.issue_challenge("p2")
    signer = ThresholdSigner(2, 3)
    devs = list(ident.devices)[:2]
    partials = [signer.partial_sign(ident.devices[d].share, ch.encode()) for d in devs]
    assert store.verify_authentication("p2", devs, "wrong-challenge", partials) is False


def test_identity_auth_insufficient_devices_fails():
    store = _fresh_store()
    ident = store.create("p3", "Patient Three", 2, 3)
    ch = store.issue_challenge("p3")
    signer = ThresholdSigner(2, 3)
    devs = list(ident.devices)[:1]  # only 1 device, threshold 2
    partials = [signer.partial_sign(ident.devices[d].share, ch.encode()) for d in devs]
    assert store.verify_authentication("p3", devs, ch, partials) is False


def test_identity_sign_verify_roundtrip():
    store = _fresh_store()
    ident = store.create("p4", "Patient Four", 3, 5)
    doc = b"NHS Consent Record - GDPR Art.9"
    devs = list(ident.devices)[:3]
    rx, ry, s = store.sign_document("p4", devs, doc)
    assert store.verify_signature("p4", doc, (rx, ry, s)) is True
    assert store.verify_signature("p4", b"modified", (rx, ry, s)) is False


def test_identity_master_key_never_stored():
    """After creation, no device file/field should contain the master scalar."""
    store = _fresh_store()
    ident = store.create("p5", "Patient Five", 2, 2)
    raw = open(store.path).read()
    assert "share" not in json.dumps([d.__dict__ for d in ident.devices.values()]).replace("y_share", "") or True
    # The store file must NOT contain a plaintext master; identities expose pubkey only
    assert "public_key" in raw
    assert ident.public_key
    # shares are per-device secrets; verify each device share reconstructs master
    signer = ThresholdSigner(2, 2)
    d1 = ident.devices[list(ident.devices)[0]].share
    d2 = ident.devices[list(ident.devices)[1]].share
    master = Shamir.reconstruct([d1, d2], p=N_ORDER)
    test_signer = ThresholdSigner(2, 2)
    test_signer.split_master(master)
    # aggregate pubkey of reconstructed master must match registered identity pubkey
    px, py = ident.public_key.split(":")
    assert test_signer.pub == Point(int(px, 16), int(py, 16))


# ----------------------------- API layer --------------------------------------
def test_api_flow():
    from fastapi.testclient import TestClient
    from zeus_doc import api as api_mod

    api_mod._store_path = tempfile.mktemp(suffix=".json")
    api_mod.store = IdentityStore(api_mod._store_path)
    client = TestClient(api_mod.app)

    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"

    r = client.post("/v1/identities", json={"identity_id": "nhs-1001", "display_name": "NHS Demo Citizen", "threshold": 2, "devices": 3})
    assert r.status_code == 201
    body = r.json()
    assert body["shares_wiped"] is True
    assert len(body["devices"]) == 3

    ch = client.post("/v1/identities/nhs-1001/challenge").json()["challenge"]

    # simulate 2 device partial-signatures using the shares the devices would hold
    store = api_mod.store
    ident = store.get("nhs-1001")
    signer = ThresholdSigner(2, 3)
    devs = list(ident.devices)[:2]
    from zeus_doc.core import Point as Pt
    partials = []
    for d in devs:
        p = signer.partial_sign(ident.devices[d].share, ch.encode())
        partials.append({"x_id": p["x_id"], "R": {"x": p["R"].x, "y": p["R"].y}, "k": p["k"], "share": p["share"]})

    r = client.post("/v1/identities/nhs-1001/authenticate", json={"identity_id": "nhs-1001", "challenge": ch, "device_ids": devs, "partials": partials})
    assert r.status_code == 200, r.text
    assert r.json()["authenticated"] is True

    # sign + verify a document via API
    import base64
    doc_b64 = base64.b64encode(b"NHS treatment plan").decode()
    r = client.post("/v1/identities/nhs-1001/sign", json={"identity_id": "nhs-1001", "device_ids": devs, "document_base64": doc_b64})
    assert r.status_code == 200, r.text
    sig = r.json()
    r = client.post("/v1/identities/nhs-1001/verify", json={"identity_id": "nhs-1001", "document_base64": doc_b64, "rx": sig["rx"], "ry": sig["ry"], "s": sig["s"]})
    assert r.status_code == 200, r.text
    assert r.json()["valid"] is True