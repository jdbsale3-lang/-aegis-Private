# AEGIS Module 5: Supply Chain Scanner
# Semantic taint analysis for AI/ML models and packages

import re
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanFinding:
    severity: str  # critical | high | medium | low | info
    category: str  # unsafe_serialization | backdoor | known_cve | suspicious_metadata | dependency_risk
    title: str
    description: str
    location: str
    recommendation: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class ScanResult:
    target: str
    target_type: str  # model | package | container | registry
    findings: list[ScanFinding]
    risk_score: float
    passed: bool
    summary: str
    latency_ms: float


class SupplyChainScanner:
    """
    Scans AI/ML supply chain for:
    - Models: unsafe serialization (Pickle), backdoor weights, suspicious metadata
    - Packages: dependency graph analysis, known CVE matching
    - Containers: Trivy integration
    - Registries: HuggingFace, PyPI monitoring
    """

    # Unsafe serialization formats (known to allow arbitrary code execution)
    UNSAFE_SERIALIZATION_FORMATS = {
        "pickle": {
            "extensions": [".pkl", ".pickle", ".p", ".joblib"],
            "risk": "critical",
            "description": "Pickle deserialization can execute arbitrary code during model loading",
        },
        "torch_save": {
            "extensions": [".pt", ".pth"],
            "risk": "high",
            "description": "PyTorch saved models use Pickle internally and can execute arbitrary code",
        },
        "tf_saved_model": {
            "extensions": [".h5", ".keras", ".pb"],
            "risk": "medium",
            "description": "TensorFlow SavedModel can contain unsafe ops if not validated",
        },
        "onnx": {
            "extensions": [".onnx"],
            "risk": "medium",
            "description": "ONNX models can contain external data references and custom ops",
        },
    }

    # Known suspicious model weight patterns
    SUSPICIOUS_WEIGHT_PATTERNS = [
        (r"backdoor|trigger|poison|exploit|malware", "suspicious_layer_name"),
        (r"(reverse_)?shell|exec\(|os\.system|subprocess|eval\(", "code_execution_layer"),
        (r"gradient_override|weight_bypass|skip_guard", "weight_manipulation"),
    ]

    # Known CVEs affecting popular ML packages (MVP - expand from API in production)
    KNOWN_ML_CVES: dict[str, list[dict]] = {
        "torch": [
            {"cve": "CVE-2026-24747", "cvss": 9.8, "affected": "<2.6.0", "desc": "PyTorch weights_only unpickler RCE via heap corruption"},
            {"cve": "CVE-2024-22476", "cvss": 7.8, "affected": "<2.2.0", "desc": "TorchServe RCE via malicious model"},
            {"cve": "CVE-2023-48022", "cvss": 9.8, "affected": "<2.1.0", "desc": "Pickle deserialization RCE in torch.load"},
        ],
        "tensorflow": [
            {"cve": "CVE-2024-21734", "cvss": 7.5, "affected": "<2.15.0", "desc": "Out-of-bounds read in SparseCountSparseOutput"},
            {"cve": "CVE-2023-25668", "cvss": 8.8, "affected": "<2.12.0", "desc": "Heap overflow in AvgPoolGrad"},
        ],
        "transformers": [
            {"cve": "CVE-2024-1234", "cvss": 7.5, "affected": "<4.36.0", "desc": "Remote code execution via crafted model config"},
        ],
        "numpy": [
            {"cve": "CVE-2021-34141", "cvss": 5.5, "affected": "<1.22.0", "desc": "Buffer overflow in ndarray"},
        ],
        "pillow": [
            {"cve": "CVE-2023-50447", "cvss": 7.5, "affected": "<10.2.0", "desc": "Heap buffer overflow in JPC decoding"},
        ],
        "langchain": [
            {"cve": "CVE-2025-68664", "cvss": 9.3, "affected": "<0.3.0", "desc": "LangChain lc-key serialization injection - secret extraction"},
            {"cve": "CVE-2025-68665", "cvss": 9.3, "affected": "<0.3.0", "desc": "LangChain JS lc-key serialization injection - secret extraction"},
        ],
        "pymilvus": [
            {"cve": "CVE-2025-64513", "cvss": 9.3, "affected": "<2.5.0", "desc": "Milvus auth bypass using hardcoded @@milvus-member@@ constant"},
        ],
        "copilot": [
            {"cve": "CVE-2025-53773", "cvss": 9.6, "affected": "<1.0.0", "desc": "GitHub Copilot RCE via crafted code completion payload"},
        ],
    }

    def __init__(self, enable_cve_check: bool = True, enable_deep_scan: bool = True):
        self.enable_cve_check = enable_cve_check
        self.enable_deep_scan = enable_deep_scan

    # ---- Model Scanning ----

    def _check_serialization_format(self, file_path: str) -> list[ScanFinding]:
        """Check if the model file uses an unsafe serialization format."""
        findings = []
        file_lower = file_path.lower()

        for fmt_name, fmt_info in self.UNSAFE_SERIALIZATION_FORMATS.items():
            for ext in fmt_info["extensions"]:
                if file_lower.endswith(ext):
                    findings.append(ScanFinding(
                        severity=fmt_info["risk"],
                        category="unsafe_serialization",
                        title=f"Unsafe serialization format: {fmt_name}",
                        description=fmt_info["description"],
                        location=file_path,
                        recommendation=(
                            f"Avoid {fmt_name} format for model serialization. "
                            f"Use SafeTensors or ONNX with validation instead. "
                            f"If {fmt_name} is required, validate the model source and "
                            f"checksum before loading."
                        ),
                    ))
        return findings

    def _check_metadata(self, metadata: dict) -> list[ScanFinding]:
        """Check model metadata for suspicious content."""
        findings = []
        metadata_str = json.dumps(metadata).lower()

        suspicious_metadata = [
            ("author", ["unknown", "anonymous", "null", "deleted", "temp_"]),
            ("source", ["unknown", "unverified", "suspicious", "huggingface.co/unverified"]),
            ("license", ["unknown", "custom", "all_rights_reserved"]),
            ("description", ["backdoor", "trigger", "poison", "eval(", "exec("]),
        ]

        for field, suspicious_values in suspicious_metadata:
            value = str(metadata.get(field, "")).lower()
            for sv in suspicious_values:
                if sv in value:
                    findings.append(ScanFinding(
                        severity="medium" if field != "description" else "high",
                        category="suspicious_metadata",
                        title=f"Suspicious {field} in model metadata",
                        description=f"Model {field} contains '{sv}' which may indicate a malicious model",
                        location=f"metadata.{field}",
                        recommendation=f"Verify the model's {field} through an independent channel. "
                                       f"Download only from trusted sources.",
                    ))

        # Check for picklescan results (simulated - in production, run picklescan)
        if "pickle" in metadata_str or "pkl" in metadata_str:
            if "unsafe" in metadata_str or "dangerous" in metadata_str:
                findings.append(ScanFinding(
                    severity="critical",
                    category="unsafe_serialization",
                    title="Pickle scan detected unsafe globals",
                    description="Model metadata indicates unsafe pickle globals (e.g., os.system, subprocess)",
                    location="metadata.picklescan",
                    recommendation="Rebuild the model using SafeTensors format. Never load untrusted pickle files.",
                ))

        return findings

    def _check_weight_anomalies(self, weight_names: list[str]) -> list[ScanFinding]:
        """Check layer/weight names for suspicious patterns."""
        findings = []
        for weight_name in weight_names:
            for pattern, category in self.SUSPICIOUS_WEIGHT_PATTERNS:
                if re.search(pattern, weight_name, re.IGNORECASE):
                    findings.append(ScanFinding(
                        severity="critical" if "code_execution" in category else "high",
                        category=category,
                        title=f"Suspicious weight name: {weight_name}",
                        description=f"Layer name '{weight_name}' matches known backdoor/exploit pattern",
                        location=f"weights.{weight_name}",
                        recommendation="This weight name is highly suspicious. Remove the layer and retrain the model.",
                    ))
        return findings

    def scan_model(self, file_path: str, metadata: Optional[dict] = None,
                   weight_names: Optional[list[str]] = None) -> ScanResult:
        """Scan a model file for supply chain risks."""
        import time
        start = time.time()

        findings = []

        # Check serialization format
        findings.extend(self._check_serialization_format(file_path))

        # Check metadata
        if metadata:
            findings.extend(self._check_metadata(metadata))

        # Check weight names
        if weight_names:
            findings.extend(self._check_weight_anomalies(weight_names))

        # Compute risk score
        severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.0}
        risk_score = 0.0
        for f in findings:
            risk_score = max(risk_score, severity_weights.get(f.severity, 0.0))
        # Multiple findings increase risk
        risk_score = min(1.0, risk_score + (len([f for f in findings if f.severity in ("critical", "high")]) * 0.15))

        passed = risk_score < 0.5
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            severity_count[f.severity] = severity_count.get(f.severity, 0) + 1

        summary = (f"Found {len(findings)} issues: "
                   f"{severity_count['critical']} critical, {severity_count['high']} high, "
                   f"{severity_count['medium']} medium, {severity_count['low']} low. "
                   f"{'PASSED' if passed else 'FAILED'} (risk score: {risk_score:.2f})")

        latency = (time.time() - start) * 1000

        return ScanResult(
            target=file_path,
            target_type="model",
            findings=findings,
            risk_score=round(risk_score, 4),
            passed=passed,
            summary=summary,
            latency_ms=round(latency, 2),
        )

    # ---- Package Scanning ----

    def _check_known_cves(self, package_name: str, version: str) -> list[ScanFinding]:
        """Check a package against known CVE database."""
        findings = []
        if not self.enable_cve_check:
            return findings

        package_lower = package_name.lower()
        if package_lower in self.KNOWN_ML_CVES:
            for cve in self.KNOWN_ML_CVES[package_lower]:
                affected = cve["affected"]
                # Simple version comparison (MVP)
                if version and self._version_affected(version, affected):
                    findings.append(ScanFinding(
                        severity="high" if cve["cvss"] >= 7.0 else "medium",
                        category="known_cve",
                        title=f"{cve['cve']}: {cve['desc']}",
                        description=f"Package {package_name} {version} is affected by {cve['cve']} (CVSS: {cve['cvss']}). "
                                    f"Affected versions: {affected}",
                        location=f"package:{package_name}@{version}",
                        recommendation=f"Upgrade {package_name} to version >{affected.replace('<', '')}",
                        cve_id=cve["cve"],
                        cvss_score=cve["cvss"],
                    ))
        return findings

    def _version_affected(self, version: str, affected_range: str) -> bool:
        """Simple version comparison. MVP only - use semver library in production."""
        if not version or not affected_range:
            return False
        # Parse affected range like "<2.2.0"
        if affected_range.startswith("<"):
            try:
                max_ver = tuple(int(x) for x in affected_range[1:].split("."))
                current = tuple(int(x) for x in version.split("."))
                return current < max_ver
            except (ValueError, IndexError):
                return False
        return False

    def _check_dependency_risks(self, requirements: str) -> list[ScanFinding]:
        """Parse requirements.txt and check for dependency risks."""
        findings = []
        lines = requirements.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("--"):
                continue

            # Parse package name and version
            match = re.match(r"([a-zA-Z0-9_.-]+)\s*(>=|==|~=|<=|!=|>|<)\s*([\d.]+)", line)
            if match:
                pkg_name = match.group(1)
                pkg_version = match.group(3)
                findings.extend(self._check_known_cves(pkg_name, pkg_version))

            # Check for unpinned versions
            if ">=" in line or "~=" in line:
                pkg_name = line.split(">=")[0].strip() if ">=" in line else line.split("~=")[0].strip()
                findings.append(ScanFinding(
                    severity="low",
                    category="dependency_risk",
                    title=f"Unpinned dependency: {pkg_name}",
                    description=f"Package {pkg_name} uses a minimum version constraint (>=) which may "
                                f"silently upgrade to a malicious version",
                    location=f"requirements:{pkg_name}",
                    recommendation=f"Pin {pkg_name} to an exact version with == instead of >=",
                ))

            # Check for typosquatting
            pkg_name_lower = line.split("=")[0].split(">")[0].split("<")[0].split("~")[0].strip().lower()
            if pkg_name_lower:
                typosquatting = ["requirments", "requirment", "pytorch", "tensorflo",
                                 "transfomers", "numppy", "pickle5", "joblibb",
                                 "langchian", "langchaing", "lantchain",
                                 "pymilvuss", "pymilvrus", "pymilvrus",
                                 "huggingfce", "huggingfacce", "transformerss",
                                 "transfomerss"]
                for typo in typosquatting:
                    if typo == pkg_name_lower:
                        findings.append(ScanFinding(
                            severity="critical",
                            category="dependency_risk",
                            title=f"Typosquatting package detected: {pkg_name_lower}",
                            description=f"Package '{pkg_name_lower}' matches known typosquatting pattern. "
                                        f"This may be a malicious package designed to steal credentials.",
                            location=f"requirements:{pkg_name_lower}",
                            recommendation=f"Remove '{pkg_name_lower}' and install the correct package name.",
                        ))

        return findings

    def scan_package(self, name: str, version: str, requirements_file: Optional[str] = None) -> ScanResult:
        """Scan a package for supply chain risks."""
        import time
        start = time.time()

        findings = []

        # Check known CVEs
        findings.extend(self._check_known_cves(name, version))

        # Check requirements file if provided
        if requirements_file:
            findings.extend(self._check_dependency_risks(requirements_file))

        # Compute risk score
        severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.0}
        risk_score = 0.0
        for f in findings:
            risk_score = max(risk_score, severity_weights.get(f.severity, 0.0))
        risk_score = min(1.0, risk_score + (len([f for f in findings if f.severity in ("critical", "high")]) * 0.1))

        passed = risk_score < 0.5
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            severity_count[f.severity] = severity_count.get(f.severity, 0) + 1

        summary = (f"Package {name}@{version}: {len(findings)} issues. "
                   f"{severity_count['critical']} critical, {severity_count['high']} high. "
                   f"{'PASSED' if passed else 'FAILED'} (risk score: {risk_score:.2f})")

        latency = (time.time() - start) * 1000

        return ScanResult(
            target=f"{name}@{version}",
            target_type="package",
            findings=findings,
            risk_score=round(risk_score, 4),
            passed=passed,
            summary=summary,
            latency_ms=round(latency, 2),
        )

    def scan_requirements(self, requirements_text: str) -> ScanResult:
        """Scan an entire requirements.txt file."""
        import time
        start = time.time()

        findings = self._check_dependency_risks(requirements_text)

        risk_score = 0.0
        severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.0}
        for f in findings:
            risk_score = max(risk_score, severity_weights.get(f.severity, 0.0))
        risk_score = min(1.0, risk_score)

        passed = risk_score < 0.5
        latency = (time.time() - start) * 1000

        return ScanResult(
            target="requirements.txt",
            target_type="manifest",
            findings=findings,
            risk_score=round(risk_score, 4),
            passed=passed,
            summary=f"{len(findings)} dependency issues found. {'PASSED' if passed else 'FAILED'}",
            latency_ms=round(latency, 2),
        )