#!/usr/bin/env python3
"""AEGIS geo/IPinfo smoke test for CI.

Validates the IPinfo token + geo responses used by the AEGIS geo/WAF
allowlist (P1). Checks known-stable lookups and the response shape.

Requires env: IPINFO_TOKEN
Run:  IPINFO_TOKEN=xxx python3 scripts/geo_smoke.py
Exit code 0 = pass, non-zero = fail. All IP belongs to JDB Sales.
"""
import json
import os
import sys
import urllib.request

TOKEN = os.environ.get("IPINFO_TOKEN", "")
if not TOKEN:
    print("SKIP: IPINFO_TOKEN not set")
    sys.exit(0)

# Verified lookups (from live testing 28 Aug 2026)
EXPECTED = {
    "8.8.8.8": ("US", "United States"),
    "51.77.53.162": ("PL", "Poland"),
}

fails = []
for ip, (cc, country) in EXPECTED.items():
    try:
        req = urllib.request.Request(
            f"https://api.ipinfo.io/lite/{ip}",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode())
        got_cc = d.get("country_code")
        got_country = d.get("country")
        ok = got_cc == cc
        print(
            f"{'PASS' if ok else 'FAIL'} {ip} -> {got_cc}/{got_country} "
            f"(expect {cc}/{country}) asn={d.get('asn')}"
        )
        if not ok:
            fails.append(ip)
    except Exception as e:
        print(f"FAIL {ip} -> error: {e}")
        fails.append(ip)

# Response-shape sanity for an additional IP (any country is fine, shape must be intact)
try:
    req = urllib.request.Request(
        "https://api.ipinfo.io/lite/8.8.4.4",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        d = json.loads(r.read().decode())
    shape_ok = all(k in d for k in ("ip", "asn", "as_name", "country_code", "country", "continent_code"))
    print(f"{'PASS' if shape_ok else 'FAIL'} shape check -> keys={sorted(d.keys())}")
    if not shape_ok:
        fails.append("shape")
except Exception as e:
    print(f"FAIL shape -> {e}")
    fails.append("shape")

if fails:
    print("GEO SMOKE FAILED:", fails)
    sys.exit(1)
print("GEO SMOKE OK")