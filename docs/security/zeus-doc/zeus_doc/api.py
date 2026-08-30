"""
ZEUS DOC — API service.

Exposes the tokenless, passwordless identity + signing functions as a REST API.
Designed as the identity backbone for the ZEUSTA NHS ID Card system and beyond.

Endpoints:
  POST /v1/identities                  create identity (master key split, never stored whole)
  GET  /v1/identities/{id}             identity summary (no secrets)
  POST /v1/identities/{id}/challenge   issue authentication challenge
  POST /v1/identities/{id}/authenticate  passwordless co-signature auth
  POST /v1/identities/{id}/sign        sign a document (t-of-n)
  POST /v1/identities/{id}/verify      verify a signature
  GET  /health                         service health

All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.
"""
from __future__ import annotations

import json
import os
import secrets
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .identity import IdentityStore

app = FastAPI(title="ZEUS DOC — Digital Operations & Certificates", version="1.0.0")

_store_path = os.environ.get("ZEUS_DOC_STORE", "zeus_doc_store.json")
store = IdentityStore(_store_path)


# --- request/response models ---------------------------------------------------
class CreateIdentityRequest(BaseModel):
    identity_id: str
    display_name: str
    threshold: int = 2
    devices: int = 3


class ChallengeResponse(BaseModel):
    identity_id: str
    challenge: str


class AuthenticateRequest(BaseModel):
    identity_id: str
    challenge: str
    device_ids: List[str]
    partials: List[dict]


class SignRequest(BaseModel):
    identity_id: str
    device_ids: List[str]
    document_base64: str  # base64 of the document bytes


class VerifyRequest(BaseModel):
    identity_id: str
    document_base64: str
    rx: int
    ry: int
    s: int


# --- helpers ---------------------------------------------------------------------
def _b64(s: str) -> bytes:
    import base64
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise HTTPException(400, "invalid base64")


@app.get("/health")
def health():
    return {"service": "zeus-doc", "status": "ok", "version": "1.0.0"}


@app.post("/v1/identities", status_code=201)
def create_identity(req: CreateIdentityRequest):
    if not (1 <= req.threshold <= req.devices <= 5):
        raise HTTPException(400, "threshold must satisfy 1 <= t <= n <= 5")
    try:
        ident = store.create(req.identity_id, req.display_name, req.threshold, req.devices)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return {
        "identity_id": ident.identity_id,
        "display_name": ident.display_name,
        "public_key": ident.public_key,
        "threshold": ident.threshold,
        "devices": [d.device_id for d in ident.devices.values()],
        "shares_wiped": True,  # master secret destroyed after split
    }


@app.get("/v1/identities/{identity_id}")
def get_identity(identity_id: str):
    ident = store.get(identity_id)
    if not ident:
        raise HTTPException(404, "unknown identity")
    return {
        "identity_id": ident.identity_id,
        "display_name": ident.display_name,
        "public_key": ident.public_key,
        "threshold": ident.threshold,
        "devices": [d.device_id for d in ident.devices.values()],
    }


@app.post("/v1/identities/{identity_id}/challenge")
def issue_challenge(identity_id: str):
    try:
        challenge = store.issue_challenge(identity_id)
    except KeyError:
        raise HTTPException(404, "unknown identity")
    return ChallengeResponse(identity_id=identity_id, challenge=challenge)


@app.post("/v1/identities/{identity_id}/authenticate")
def authenticate(identity_id: str, req: AuthenticateRequest):
    try:
        ok = store.verify_authentication(identity_id, req.device_ids, req.challenge, req.partials)
    except Exception:
        raise HTTPException(401, "authentication failed")
    if not ok:
        raise HTTPException(401, "authentication failed")
    return {"authenticated": True, "identity_id": identity_id, "method": "tokenless-passwordless", "factor": "t-of-n-threshold"}


@app.post("/v1/identities/{identity_id}/sign")
def sign_document(identity_id: str, req: SignRequest):
    document = _b64(req.document_base64)
    try:
        rx, ry, s = store.sign_document(identity_id, req.device_ids, document)
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"identity_id": identity_id, "rx": rx, "ry": ry, "s": s, "algorithm": "t-of-n-schnorr"}


@app.post("/v1/identities/{identity_id}/verify")
def verify_signature(identity_id: str, req: VerifyRequest):
    document = _b64(req.document_base64)
    ok = store.verify_signature(identity_id, document, (req.rx, req.ry, req.s))
    if not ok:
        raise HTTPException(400, "signature invalid")
    return {"valid": True, "identity_id": identity_id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("zeus_doc.api:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8400")))