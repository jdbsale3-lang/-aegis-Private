# AEGIS self-scan gate: AEGIS's OWN requirements.txt must never contain
# unpinned / CVE-flagged dependencies.
# This is the permanent fix for the "unpinned flask" class of issue:
# any future dependency added without a strict version pin FAILS CI here.
#
# All IP belongs to JDB Sales.

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.supply_chain.scanner import SupplyChainScanner


def _own_requirements() -> str:
    """Read AEGIS's own backend requirements.txt (relative to this test file)."""
    path = os.path.join(os.path.dirname(__file__), "..", "requirements.txt")
    with open(path) as f:
        return f.read()


def test_aegis_own_requirements_are_fully_pinned():
    """Every dependency in AEGIS's own manifest must be strictly pinned (==).

    Unpinned constraints (>=, <=, no version) introduce supply-chain and
    reproducibility risk. The scanner flags them as dependency_risk.
    """
    requirements = _own_requirements()
    # quick sanity: the file actually has content
    assert requirements.strip(), "requirements.txt is empty"

    scanner = SupplyChainScanner()
    result = scanner.scan_requirements(requirements)

    unpinned = [
        f.description
        for f in result.findings
        if f.category == "dependency_risk"
        and "minimum version" in f.description.lower()
    ]
    assert (
        unpinned == []
    ), "AEGIS own requirements.txt contains unpinned dependencies: " + "; ".join(
        unpinned
    )


def test_aegis_own_requirements_have_no_findings():
    """The full gate: zero findings of any severity in AEGIS's own manifest."""
    requirements = _own_requirements()
    scanner = SupplyChainScanner()
    result = scanner.scan_requirements(requirements)
    assert result.passed is True, (
        f"AEGIS own requirements.txt FAILED supply-chain scan: "
        f"{result.summary} — {[f.title for f in result.findings]}"
    )
    assert (
        result.risk_score == 0.0
    ), f"risk_score should be 0.0, got {result.risk_score}"
