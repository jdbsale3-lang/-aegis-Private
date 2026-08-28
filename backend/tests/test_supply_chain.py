# Tests for AEGIS Module 5: Supply Chain Scanner

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.supply_chain.scanner import SupplyChainScanner


def test_safe_model():
    scanner = SupplyChainScanner()
    result = scanner.scan_model(
        "model.safetensors",
        metadata={"author": "meta-llama", "source": "hugging.co/meta-llama", "license": "llama3"},
        weight_names=["layer1.weight", "layer2.bias", "output.weight"],
    )
    assert result.passed is True
    assert result.risk_score < 0.5


def test_unsafe_pickle_model():
    scanner = SupplyChainScanner()
    result = scanner.scan_model(
        "model.pkl",
        metadata={"author": "unknown", "source": "unknown"},
        weight_names=["layer1.weight"],
    )
    assert result.passed is False
    assert result.risk_score >= 0.5
    # Should detect unsafe serialization
    categories = [f.category for f in result.findings]
    assert "unsafe_serialization" in categories


def test_suspicious_weight_names():
    scanner = SupplyChainScanner()
    result = scanner.scan_model(
        "model.pt",
        metadata={"author": "test", "source": "test"},
        weight_names=["layer1.weight", "backdoor_trigger.weight", "output.weight"],
    )
    categories = [f.category for f in result.findings]
    assert "suspicious_layer_name" in categories


def test_suspicious_metadata():
    scanner = SupplyChainScanner()
    result = scanner.scan_model(
        "model.pt",
        metadata={"author": "anonymous", "description": "contains backdoor eval() trigger"},
        weight_names=["weight1"],
    )
    categories = [f.category for f in result.findings]
    assert "suspicious_metadata" in categories


def test_known_cve_detection():
    scanner = SupplyChainScanner(enable_cve_check=True)
    result = scanner.scan_package("torch", "2.1.0")
    assert len(result.findings) > 0
    for f in result.findings:
        if f.cve_id:
            break
    else:
        assert False, "No CVE found for torch 2.1.0"


def test_safe_package():
    scanner = SupplyChainScanner()
    result = scanner.scan_package("requests", "2.31.0")
    assert result.passed is True


def test_requirements_scan():
    scanner = SupplyChainScanner()
    requirements = """
torch==2.1.0
transformers>=4.35.0
requests==2.31.0
numpy==1.24.0
"""
    result = scanner.scan_requirements(requirements)
    # Should find at least one issue (torch CVE, unpinned transformers)
    assert len(result.findings) > 0
    categories = [f.category for f in result.findings]
    assert "known_cve" in categories


def test_unpinned_dependency():
    scanner = SupplyChainScanner()
    requirements = "torch>=2.1.0"
    result = scanner.scan_requirements(requirements)
    categories = [f.category for f in result.findings]
    assert "dependency_risk" in categories


def test_torch_save_format():
    scanner = SupplyChainScanner()
    result = scanner.scan_model(
        "model.pt",
        metadata={},
        weight_names=[],
    )
    categories = [f.category for f in result.findings]
    assert "unsafe_serialization" in categories


def test_onnx_format():
    scanner = SupplyChainScanner()
    result = scanner.scan_model("model.onnx")
    categories = [f.category for f in result.findings]
    assert "unsafe_serialization" in categories


def test_empty_scan():
    scanner = SupplyChainScanner()
    result = scanner.scan_model("model.safetensors")
    assert result.passed is True
    assert len(result.findings) == 0

def test_cve_2026_24747_range_regression():
    """FIND-2026-001 regression: torch 2.6.0 & 2.9.1 MUST fail, 2.10.0 MUST pass."""
    from modules.supply_chain.scanner import SupplyChainScanner
    sc = SupplyChainScanner(enable_cve_check=True, enable_deep_scan=False)
    for ver in ("2.6.0", "2.9.1"):
        res = sc.scan_package("torch", ver)
        assert res.passed is False, f"torch@{ver} must be flagged (CVE-2026-24747 affects <2.10.0) - got passed={res.passed}"
        assert any("2026-24747" in str(f.cve_id or "") for f in res.findings), f"torch@{ver} missing 24747 finding"
    res = sc.scan_package("torch", "2.10.0")
    assert res.passed is True, f"torch@2.10.0 must pass (fixed) - got passed={res.passed}"

def test_cve_remediation_points_to_fixed():
    """Recommendation must say 2.10.0 or later (not the stale >2.6.0)."""
    from modules.supply_chain.scanner import SupplyChainScanner
    sc = SupplyChainScanner(enable_cve_check=True, enable_deep_scan=False)
    res = sc.scan_package("torch", "2.1.0")
    recs = [f.recommendation for f in res.findings if "24747" in str(f.cve_id or "")]
    assert recs and "2.10.0" in recs[0], f"remediation should point to 2.10.0, got {recs[:1]}"
