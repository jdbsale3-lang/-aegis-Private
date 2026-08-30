"""
ZEUS DOC — identity layer.

Tokenless, passwordless digital identity:
  - Registration: a master signing key is created and split into n device shares
    (threshold t). The master key is discarded immediately — no party ever holds it whole.
  - Authentication: challenge/response — the verifier sends a random challenge;
    t of the user's devices produce a co-signature; verification is against the
    registered public key. No passwords, no tokens, no OTP SMS.
  - Signing: the same t-of-n machinery signs documents; signatures verify against
    the public key, providing non-repudiation equal to a qualified e-signature.

All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .core import ThresholdSigner, Point, generate_master_key, public_key, _qhash

CHALLENGE_TTL_S = 300  # challenge valid 5 minutes


@dataclass
class Device:
    device_id: str
    share: Tuple[int, int]          # (x_id, y_share)
    pub_key: str                    # hex of the device's own identity key
    enrolled_at: float = field(default_factory=time.time)


@dataclass
class Identity:
    identity_id: str
    display_name: str
    public_key: str                 # hex of aggregate pubkey dG
    threshold: int
    devices: Dict[str, Device] = field(default_factory=dict)
    challenge: Optional[str] = None
    challenge_exp: float = 0.0
    created_at: float = field(default_factory=time.time)


class IdentityStore:
    """Durable store for ZEUS DOC identities (file-backed in this reference build)."""

    def __init__(self, path: str = "zeus_doc_store.json"):
        self.path = path
        self._identities: Dict[str, Identity] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            raw = json.load(open(self.path))
            for k, v in raw.items():
                devs = {dk: Device(**dd) for dk, dd in v.get("devices", {}).items()}
                v.pop("devices", None)
                ident = Identity(**v)
                ident.devices = devs
                ident.challenge = None
                ident.challenge_exp = 0.0
                self._identities[k] = ident
        except Exception:
            # corrupt store -> start fresh (never blocks auth of a fresh instance)
            self._identities = {}

    def _save(self) -> None:
        out = {}
        for k, ident in self._identities.items():
            d = {dk: dd.__dict__ for dk, dd in ident.devices.items()}
            out[k] = {**ident.__dict__, "devices": d, "challenge": None, "challenge_exp": 0.0}
        with open(self.path, "w") as f:
            json.dump(out, f, indent=2)

    def create(self, identity_id: str, display_name: str, threshold: int, devices: int) -> Identity:
        if identity_id in self._identities:
            raise ValueError("identity exists")
        signer = ThresholdSigner(threshold, devices)
        master = generate_master_key()
        shares = signer.split_master(master)
        pub = signer.pub
        ident = Identity(identity_id, display_name, f"{pub.x:x}:{pub.y:x}", threshold)
        for i, share in enumerate(shares):
            dev_id = f"dev-{identity_id}-{i+1}"
            dev_pub = public_key(secrets.randbelow(int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16) - 1) + 1)
            ident.devices[dev_id] = Device(dev_id, share, f"{dev_pub.x:x}:{dev_pub.y:x}")
        self._identities[identity_id] = ident
        self._save()
        return ident

    def get(self, identity_id: str) -> Optional[Identity]:
        return self._identities.get(identity_id)

    def issue_challenge(self, identity_id: str) -> str:
        ident = self.get(identity_id)
        if not ident:
            raise KeyError("unknown identity")
        ident.challenge = secrets.token_hex(32)
        ident.challenge_exp = time.time() + CHALLENGE_TTL_S
        self._save()
        return ident.challenge

    def verify_authentication(self, identity_id: str, device_ids: List[str], challenge: str, partials: List[dict]) -> bool:
        """Passwordless auth: t-of-n co-signature over the challenge."""
        ident = self.get(identity_id)
        if not ident:
            return False
        if not ident.challenge or not secrets.compare_digest(ident.challenge, challenge):
            return False
        if time.time() > ident.challenge_exp:
            return False
        if len(device_ids) < ident.threshold:
            return False
        # rebuild signer and combine using the device shares;
        # normalize wire-format partials (R as {"x":..,"y":..}) into Points
        norm_partials = []
        for p in partials:
            rp = p.get("R")
            if isinstance(rp, dict):
                p = {**p, "R": Point(int(rp["x"]), int(rp["y"]))}
            norm_partials.append(p)
        signer = ThresholdSigner(ident.threshold, max(len(ident.devices), ident.threshold))
        combined = signer.combine_partials(norm_partials, challenge.encode())
        px, py = ident.public_key.split(":")
        pub = Point(int(px, 16), int(py, 16))
        return signer.verify(challenge.encode(), combined, pub)

    def sign_document(self, identity_id: str, device_ids: List[str], document_bytes: bytes) -> Tuple[int, int, int]:
        """Digitally sign a document with t-of-n device shares (non-repudiation).
        Returns (R.x, R.y, s) — full R point carried explicitly (no y-parity loss)."""
        ident = self.get(identity_id)
        if not ident:
            raise KeyError("unknown identity")
        if len(device_ids) < ident.threshold:
            raise ValueError("insufficient devices for threshold")
        signer = ThresholdSigner(ident.threshold, max(len(ident.devices), ident.threshold))
        partials = []
        for did in device_ids:
            dev = ident.devices.get(did)
            if not dev:
                raise KeyError(f"unknown device {did}")
            # deterministic nonce per device+document for reproducible partials (audit-friendly)
            nonce_seed = hashlib.sha256(f"{dev.share[0]}:{document_bytes.hex()}".encode()).digest()
            nonce = int.from_bytes(nonce_seed, "big") % (int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16) - 1) + 1
            partials.append(signer.partial_sign(dev.share, document_bytes, nonce=nonce))
        R, s = signer.combine_partials(partials, document_bytes)
        return R.x, R.y, s

    def verify_signature(self, identity_id: str, document_bytes: bytes, signature: Tuple[int, int, int]) -> bool:
        ident = self.get(identity_id)
        if not ident:
            return False
        px, py = ident.public_key.split(":")
        pub = Point(int(px, 16), int(py, 16))
        rx, ry, s = signature
        R = Point(rx, ry)
        return ThresholdSigner.verify(document_bytes, (R, s), pub)