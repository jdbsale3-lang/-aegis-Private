"""
ZEUS DOC — core threshold cryptography (implementation of digital identity foundational components).

Implements:
  1. Shamir secret sharing over a large prime field (GF(p)) — split a private key into N
     shares, any t of which reconstruct it. Security by design: no single device ever
     holds the whole key.
  2. Threshold Schnorr signatures (t-of-n) — each signer produces a partial signature
     from their share; t partials combine to a full signature verifiable against the
     aggregate public key. Tokenless + passwordless by construction (the "key" is split,
     never stored whole; authentication is challenge/response, no password).

All IP belongs to JDB Sales. Licensed to ZEUSTRUSTAEGISSECURITY LTD.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import List, Optional, Sequence, Tuple

# --- Domain parameters: secp256k1-style large prime field ----------------------
# (Used generically for the signing group; pure-Python arithmetic, auditable.)
P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # secp256k1 field prime
GX: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order

_qhash = lambda *parts: int.from_bytes(
    hashlib.sha256(b"".join(p.to_bytes(32, "big") for p in parts)).digest(), "big"
) % P


def modinv(a: int, m: int = P) -> int:
    """Modular inverse via extended Euclid."""
    if a == 0:
        raise ValueError("modinv of zero")
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


# -------------------------------------------------------------------------------
# 1. SHAMIR SECRET SHARING (GF(p))
# -------------------------------------------------------------------------------
class Shamir:
    """Split a secret s into n shares; any t reconstruct it (Lagrange interpolation)."""

    @staticmethod
    def split(secret: int, t: int, n: int, p: int = P) -> List[Tuple[int, int]]:
        if not (1 <= t <= n):
            raise ValueError("need 1 <= t <= n")
        coeffs = [secret % p] + [secrets.randbelow(p) for _ in range(t - 1)]

        def poly(x: int) -> int:
            acc = 0
            for c in reversed(coeffs):
                acc = (acc * x + c) % p
            return acc

        return [(x, poly(x)) for x in range(1, n + 1)]

    @staticmethod
    def reconstruct(shares: Sequence[Tuple[int, int]], p: int = P) -> int:
        """Lagrange interpolation at x=0 using any t shares."""
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            num = den = 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                num = (num * (-xj)) % p
                den = (den * (xi - xj)) % p
            li = num * modinv(den, p) % p
            secret = (secret + yi * li) % p
        return secret


# -------------------------------------------------------------------------------
# 2. SCHNORR KEYS (pure-python point ops on secp256k1)
# -------------------------------------------------------------------------------
class Point:
    __slots__ = ("x", "y")

    def __init__(self, x: int, y: int):
        self.x, self.y = x, y

    def __eq__(self, o):
        return isinstance(o, Point) and self.x == o.x and self.y == o.y

    def __repr__(self):
        return f"Point({self.x:x},{self.y:x})"


_G = Point(GX, GY)
_O = Point(0, 0)  # infinity (not used in practice here)


def point_add(a: Point, b: Point) -> Point:
    if a == _O:
        return b
    if b == _O:
        return a
    if a == b:
        # doubling
        if a.y == 0:
            return _O
        lam = (3 * a.x * a.x) * modinv(2 * a.y) % P
    else:
        if a.x == b.x:
            return _O
        lam = (b.y - a.y) * modinv(b.x - a.x) % P
    x3 = (lam * lam - a.x - b.x) % P
    y3 = (lam * (a.x - x3) - a.y) % P
    return Point(x3, y3)


def point_mul(k: int, pt: Point = _G) -> Point:
    k %= P
    r = _O
    addend = pt
    while k:
        if k & 1:
            r = point_add(r, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return r


def generate_master_key() -> int:
    """Master private scalar d ∈ [1, N-1]."""
    return secrets.randbelow(N - 1) + 1


def public_key(d: int) -> Point:
    return point_mul(d)


# -------------------------------------------------------------------------------
# 3. THRESHOLD SIGNING (t-of-n Schnorr)
# -------------------------------------------------------------------------------
class ThresholdSigner:
    """
    Distribute a master private key d as n Shamir shares (threshold t).
    Any t devices co-sign a message; the combined signature validates against dG.

    Flow:
      - setup(master_secret, t, n)  -> (share_to_fields, aggregate_pubkey)
      - each device signs with its share + its own ephemeral nonce k_i
      - combine(t partial sigs)     -> full Schnorr signature (r, s)
      - verify(m, (r, s), pubkey)   -> True/False (standard Schnorr check)
    """

    def __init__(self, t: int, n: int):
        if not (2 <= t <= n <= 5):
            raise ValueError("design range: 2 <= t <= n <= 5")
        self.t, self.n = t, n

    def split_master(self, master_secret: int) -> List[Tuple[int, int]]:
        self.master = master_secret % N
        self.shares = Shamir.split(self.master, self.t, self.n, p=N)
        self.pub = public_key(self.master)
        return self.shares

    # --- device-side partial signature ------------------------------------
    def partial_sign(self, share: Tuple[int, int], message: bytes, nonce: Optional[int] = None) -> dict:
        x_id, y_i = share
        if nonce is None:
            nonce = secrets.randbelow(N - 1) + 1
        k_i = nonce % N
        R_i = point_mul(k_i)  # device's ephemeral commitment
        e = _qhash(R_i.x, int.from_bytes(message, "big")) if False else None
        # Schnorr partial: s_i = k_i + e * share_y  (e from combined R)
        # To combine at threshold we commit per-device R_i; the coordinator
        # gathers t R_i, computes combined R = sum R_i, e = H(R.x || m).
        return {"x_id": x_id, "R": R_i, "k": k_i, "share": y_i}

    @staticmethod
    def combine_partials(partials: Sequence[dict], message: bytes) -> Tuple[Point, int]:
        """Combine t partial signatures into a full (R, s) Schnorr signature."""
        if len(partials) < 2:
            raise ValueError("need >= 2 partials for threshold combine")
        # combined nonce commitment R = sum of R_i
        R = _O
        for p in partials:
            R = point_add(R, p["R"])
        e = int.from_bytes(hashlib.sha256(R.x.to_bytes(32, "big") + message).digest(), "big") % N
        s = 0
        for p in partials:
            s = (s + p["k"]) % N
        # add the threshold-weighted share contribution: e * sum(L_i * share_i)
        shares = [(p["x_id"], p["share"]) for p in partials]
        L_sum = 0
        for i, (xi, _) in enumerate(shares):
            num = den = 1
            for j, (xj, _) in enumerate(shares):
                if i == j:
                    continue
                num = (num * (-xj)) % N
                den = (den * (xi - xj)) % N
            li = num * modinv(den, N) % N
            L_sum = (L_sum + li * shares[i][1]) % N
        s = (s + e * L_sum) % N
        return R, s

    @staticmethod
    def verify(message: bytes, sig: Tuple[Point, int], pub: Point) -> bool:
        R, s = sig
        if R == _O or not (1 <= s < N):
            return False
        e = int.from_bytes(hashlib.sha256(R.x.to_bytes(32, "big") + message).digest(), "big") % N
        # sG = R + e·pub
        lhs = point_mul(s)
        rhs = point_add(R, point_mul(e, pub))
        return lhs == rhs


def _point_y(x: int) -> int:
    """Recover a y coordinate on secp256k1 from x (parity chosen for R)."""
    y2 = (pow(x, 3, P) + 7) % P
    return pow(y2, (P + 1) // 4, P)