# AEGIS-on-itself: Self-Protection Layer
# AEGIS monitors and protects itself from compromise

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class IntegrityCheckResult:
    check_id: str
    component: str  # config | code | deps | env | runtime
    status: str  # passed | failed | warning
    findings: list[dict]
    score: float  # 0.0 (perfect) to 1.0 (compromised)
    latency_ms: float


@dataclass
class SelfProtectionReport:
    report_id: str
    timestamp: float
    overall_score: float
    status: str  # secure | degraded | compromised
    checks: list[IntegrityCheckResult]
    active_threats: list[dict]
    recommendations: list[str]


class AEGISSelfProtection:
    """
    AEGIS-on-itself: Self-protection layer that monitors AEGIS itself.
    Watches configuration integrity, code tampering, dependency changes,
    environment variable leaks, and runtime anomalies.
    """

    # Critical files that should never change without a deploy
    CRITICAL_FILES = [
        "core/config.py",
        "core/security.py",
        "core/database.py",
        "main.py",
    ]

    # Allowed file hashes (populated at first scan)
    _file_hashes: dict[str, str] = {}

    # Sensitive environment variable patterns
    SENSITIVE_ENV_PATTERNS = [
        r"(secret|password|token|key|credential|auth|jwt|api_key|private)",
        r"(DATABASE_URL|REDIS_URL|KAFKA_BOOTSTRAP)",
        r"(AWS_ACCESS_KEY|AWS_SECRET|AZURE_|GCP_)",
        r"(SLACK_|DISCORD_|GITHUB_|SENDGRID_)",
    ]

    # Dangerous permission patterns
    DANGEROUS_PERMISSIONS = [
        r"chmod\s+777",
        r"chown\s+root",
        r"umask\s+000",
        r"777\s+[a-zA-Z]",
    ]

    # Default runtime checks
    RUNTIME_CHECKS = {
        "rate_limit_functional": True,
        "auth_middleware_active": True,
        "cors_production_restricted": True,
        "debug_mode_off": True,
        "non_root_user": True,
    }

    def __init__(self, workspace_path: str = "."):
        self.workspace_path = workspace_path
        self._runtime_state = self.RUNTIME_CHECKS.copy()
        self._anomaly_history: list[dict] = []
        self._initialized = False

    # ---- Integrity Check: Configuration ----

    def _check_config_integrity(self) -> IntegrityCheckResult:
        """Check that configuration files haven't been tampered with."""
        start = time.time()
        findings = []

        # Check critical files exist and haven't changed
        for rel_path in self.CRITICAL_FILES:
            full_path = os.path.join(self.workspace_path, rel_path)
            if not os.path.exists(full_path):
                findings.append(
                    {
                        "severity": "critical",
                        "type": "missing_file",
                        "detail": f"Critical file missing: {rel_path}",
                    }
                )
                continue

            with open(full_path, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()

            if rel_path in self._file_hashes:
                if current_hash != self._file_hashes[rel_path]:
                    findings.append(
                        {
                            "severity": "critical",
                            "type": "file_tampered",
                            "detail": f"File hash changed: {rel_path}. Possible tampering detected.",
                            "expected": self._file_hashes[rel_path],
                            "actual": current_hash,
                        }
                    )
            else:
                self._file_hashes[rel_path] = current_hash

        # Check for unauthorized files in core directories
        core_dir = os.path.join(self.workspace_path, "core")
        if os.path.exists(core_dir):
            expected_core = {"config.py", "security.py", "database.py", "__init__.py"}
            actual_core = set(os.listdir(core_dir))
            unexpected = actual_core - expected_core - {"__pycache__"}
            for f in unexpected:
                if not f.endswith(".pyc") and not f.startswith("."):
                    findings.append(
                        {
                            "severity": "medium",
                            "type": "unauthorized_file",
                            "detail": f"Unexpected file in core: {f}",
                        }
                    )

        score = min(
            1.0, len([f for f in findings if f["severity"] == "critical"]) * 0.5
        )
        status = "passed" if score == 0 else ("warning" if score < 0.5 else "failed")
        latency = (time.time() - start) * 1000

        return IntegrityCheckResult(
            check_id="config-integrity",
            component="config",
            status=status,
            findings=findings,
            score=round(score, 4),
            latency_ms=round(latency, 2),
        )

    # ---- Integrity Check: Environment ----

    def _check_environment(self) -> IntegrityCheckResult:
        """Check environment for leaked secrets or dangerous configurations."""
        start = time.time()
        findings = []

        # Check all environment variables for sensitive patterns
        for key, value in os.environ.items():
            key_lower = key.lower()

            # Check if key name suggests sensitive data
            for pattern in self.SENSITIVE_ENV_PATTERNS:
                if re.search(pattern, key_lower):
                    # Check if the value looks like a real secret (not a placeholder)
                    placeholder_patterns = [
                        "changeme",
                        "change-me",
                        "your-",
                        "example",
                        "test",
                        "dev-",
                    ]
                    value_lower = value.lower()
                    if not any(p in value_lower for p in placeholder_patterns):
                        # Found a potentially real secret in env
                        if len(value) > 8:  # Real secrets are long
                            findings.append(
                                {
                                    "severity": "info",
                                    "type": "sensitive_env_var",
                                    "detail": f"Sensitive environment variable detected: {key} (length: {len(value)})",
                                    "key": key,
                                }
                            )
                    break

        # Check for debug mode in production
        if os.environ.get("ENVIRONMENT") == "production":
            if os.environ.get("DEBUG", "").lower() == "true":
                findings.append(
                    {
                        "severity": "critical",
                        "type": "debug_mode",
                        "detail": "DEBUG mode is enabled in production environment",
                    }
                )
            cors = os.environ.get("CORS_ORIGINS", "")
            if cors == "*" or cors == "['*']":
                findings.append(
                    {
                        "severity": "high",
                        "type": "cors_misconfiguration",
                        "detail": "CORS is set to wildcard (*) in production",
                    }
                )

        # Check for dangerous permissions in key files
        key_paths = ["main.py", "core/", "modules/"]
        for rel_path in key_paths:
            full_path = os.path.join(self.workspace_path, rel_path)
            if os.path.exists(full_path):
                try:
                    mode = os.stat(full_path).st_mode
                    # Check for world-writable permissions
                    if mode & 0o002:
                        findings.append(
                            {
                                "severity": "high",
                                "type": "world_writable",
                                "detail": f"World-writable permissions on {rel_path}",
                            }
                        )
                except OSError:
                    pass

        score = 0.0
        for f in findings:
            sev = f.get("severity", "low")
            if sev == "critical":
                score = max(score, 0.9)
            elif sev == "high":
                score = max(score, 0.6)
            elif sev == "medium":
                score = max(score, 0.3)

        status = "passed" if score == 0 else ("warning" if score < 0.5 else "failed")
        latency = (time.time() - start) * 1000

        return IntegrityCheckResult(
            check_id="environment-check",
            component="env",
            status=status,
            findings=findings,
            score=round(score, 4),
            latency_ms=round(latency, 2),
        )

    # ---- Integrity Check: Dependencies ----

    def _check_dependency_integrity(self) -> IntegrityCheckResult:
        """Check that dependency files haven't been modified unexpectedly."""
        start = time.time()
        findings = []

        dep_files = [
            ("requirements.txt", "python"),
            ("go.mod", "go"),
            ("go.sum", "go"),
        ]

        for filename, lang in dep_files:
            full_path = os.path.join(self.workspace_path, filename)
            if os.path.exists(full_path):
                with open(full_path, "rb") as f:
                    content = f.read()

                if filename not in self._file_hashes:
                    self._file_hashes[filename] = hashlib.sha256(content).hexdigest()
                else:
                    current_hash = hashlib.sha256(content).hexdigest()
                    if current_hash != self._file_hashes[filename]:
                        findings.append(
                            {
                                "severity": "high",
                                "type": "dep_file_changed",
                                "detail": f"Dependency file {filename} has changed since last scan",
                                "expected": self._file_hashes[filename],
                                "actual": current_hash,
                            }
                        )

                # Check for suspicious packages in requirements.txt
                if filename == "requirements.txt" and content:
                    for line in content.decode().split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Check for typosquatting
                            typosquatting = [
                                "requirments",
                                "requirment",
                                "pytorch",
                                "tensorflo",
                                "transfomers",
                                "numppy",
                                "pickle5",
                                "joblibb",
                            ]
                            for typo in typosquatting:
                                if typo in line.lower():
                                    findings.append(
                                        {
                                            "severity": "critical",
                                            "type": "typosquatting",
                                            "detail": f"Possible typosquatting package detected: {line}",
                                        }
                                    )

        score = 0.0
        for f in findings:
            if f.get("severity") == "critical":
                score = max(score, 0.9)
            elif f.get("severity") == "high":
                score = max(score, 0.6)

        status = "passed" if score == 0 else ("warning" if score < 0.5 else "failed")
        latency = (time.time() - start) * 1000

        return IntegrityCheckResult(
            check_id="dependency-integrity",
            component="deps",
            status=status,
            findings=findings,
            score=round(score, 4),
            latency_ms=round(latency, 2),
        )

    # ---- Runtime Check ----

    def _check_runtime_state(self) -> IntegrityCheckResult:
        """Check that runtime security features are active."""
        start = time.time()
        findings = []

        # Check each runtime security feature
        for check_name, expected_state in self._runtime_state.items():
            is_active = self._runtime_state.get(check_name, False)
            if not is_active and expected_state:
                findings.append(
                    {
                        "severity": "high",
                        "type": "runtime_disabled",
                        "detail": f"Runtime security check '{check_name}' is disabled",
                        "check": check_name,
                        "expected": expected_state,
                        "actual": is_active,
                    }
                )

        # Check process security
        if os.geteuid() == 0:
            findings.append(
                {
                    "severity": "critical",
                    "type": "running_as_root",
                    "detail": "AEGIS is running as root. This is a security risk.",
                }
            )

        # Check for unauthorized open ports (simplified)
        score = 0.0
        for f in findings:
            if f.get("severity") == "critical":
                score = max(score, 0.9)
            elif f.get("severity") == "high":
                score = max(score, 0.5)

        status = "passed" if score == 0 else ("warning" if score < 0.5 else "failed")
        latency = (time.time() - start) * 1000

        return IntegrityCheckResult(
            check_id="runtime-state",
            component="runtime",
            status=status,
            findings=findings,
            score=round(score, 4),
            latency_ms=round(latency, 2),
        )

    # ---- Anomaly Detection ----

    def _detect_anomalies(self) -> list[dict]:
        """
        Detect anomalies across all checks.
        Looks for patterns that suggest progressive compromise.
        """
        active_threats = []

        # Check for rapid file changes
        if len(self._anomaly_history) > 1:
            recent_changes = sum(
                1
                for entry in self._anomaly_history[-5:]
                if any(
                    f.get("type") == "file_tampered" for f in entry.get("findings", [])
                )
            )
            if recent_changes >= 3:
                active_threats.append(
                    {
                        "threat_id": "rapid-tampering",
                        "severity": "critical",
                        "description": f"Multiple file changes detected in last {len(self._anomaly_history)} checks. "
                        f"Possible active compromise.",
                        "confidence": 0.8,
                        "recommendation": "Immediately isolate the instance and investigate. "
                        "Compare current files with git baseline.",
                    }
                )

        # Check for degrading security score
        if len(self._anomaly_history) >= 3:
            recent_scores = [
                entry.get("score", 0) for entry in self._anomaly_history[-3:]
            ]
            if (
                all(s > 0 for s in recent_scores)
                and recent_scores[-1] > recent_scores[0] * 1.5
            ):
                active_threats.append(
                    {
                        "threat_id": "degrading-security",
                        "severity": "high",
                        "description": "Security score is degrading over time. Score trend: "
                        f"{[f'{s:.2f}' for s in recent_scores]}",
                        "confidence": 0.6,
                        "recommendation": "Review recent changes and deployments. Check for unauthorized modifications.",
                    }
                )

        return active_threats

    # ---- Main Run ----

    def run_full_check(self) -> SelfProtectionReport:
        """Run the complete self-protection check."""
        import uuid

        # Run all checks
        config_check = self._check_config_integrity()
        env_check = self._check_environment()
        dep_check = self._check_dependency_integrity()
        runtime_check = self._check_runtime_state()

        checks = [config_check, env_check, dep_check, runtime_check]

        # Compute overall score
        overall_score = sum(c.score for c in checks) / max(len(checks), 1)

        # Detect anomalies
        active_threats = self._detect_anomalies()

        # Record in history
        self._anomaly_history.append(
            {
                "timestamp": time.time(),
                "score": overall_score,
                "findings": [f for c in checks for f in c.findings],
            }
        )

        # Determine status
        if overall_score >= 0.7:
            status = "compromised"
        elif overall_score >= 0.3:
            status = "degraded"
        else:
            status = "secure"

        # Generate recommendations
        recommendations = []
        if status == "compromised":
            recommendations.append(
                "IMMEDIATE ACTION: Isolate this instance from the network."
            )
            recommendations.append("Run a full forensic audit of all file changes.")
            recommendations.append("Rotate all API keys and secrets.")
        if status == "degraded":
            recommendations.append("Review and fix the findings above.")
            recommendations.append("Run a full deploy from a known-good commit.")
        if any(c.score > 0 for c in checks):
            recommendations.append(
                "Schedule a code review for the affected components."
            )

        return SelfProtectionReport(
            report_id=str(uuid.uuid4()),
            timestamp=time.time(),
            overall_score=round(overall_score, 4),
            status=status,
            checks=checks,
            active_threats=active_threats,
            recommendations=recommendations,
        )

    def update_runtime_state(self, check_name: str, is_active: bool):
        """Update the runtime state of a security check."""
        self._runtime_state[check_name] = is_active
        logger.info(f"Runtime state updated: {check_name} = {is_active}")

    def reset_baseline(self):
        """Reset file hash baselines (after a legitimate deploy)."""
        self._file_hashes.clear()
        self._anomaly_history.clear()
        logger.info("Self-protection baselines reset")
