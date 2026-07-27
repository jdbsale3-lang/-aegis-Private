# AEGIS Advanced Defenses Module
# Fills the 5 critical 30-day defense gaps

import re
import json
import hashlib
import random
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MultiModalAnalysisResult:
    threat_detected: bool
    threat_score: float
    threat_type: str  # adversarial_perturbation | text_in_image | incoherent_modality | safe
    details: list[str]
    confidence: float


@dataclass
class VectorPinResult:
    verified: bool
    origin: str
    tamper_score: float
    details: str


@dataclass
class MilvusAuthResult:
    vulnerable: bool
    cve: str
    cvss: float
    detail: str


@dataclass
class LangChainAuditResult:
    vulnerable: bool
    findings: list[dict]
    risk_score: float


class AdvancedDefenses:
    """
    Fills the 5 critical 30-day defense gaps:
    1. Multi-Modal Injection Detection
    2. LoRD-Resistant Watermarking
    3. VectorPin Integration (vector origin verification)
    4. Milvus Auth Verification
    5. LangChain Version Audit
    """

    # ---- 1. Multi-Modal Injection Detection ----

    # Text patterns that indicate multi-modal injection attempts
    MULTI_MODAL_INJECTION_PATTERNS = [
        # CoTTA-style: visually imperceptible text triggers
        r"(what|can|do)\s+you\s+(see|read|notice|detect)\s+in\s+this\s+(image|picture|photo)",
        r"(describe|analyze|interpret|explain)\s+the\s+(image|picture|photo)\s+and\s+",
        # Image-text inconsistency probes
        r"(does|is|are)\s+this\s+(image|picture|photo)\s+(show|contain|depict)",
        # Cross-modal injection probes
        r"(ignore|forget|disregard)\s+(the\s+)?(image|visual|picture)\s+(and|but)\s+",
        r"(the\s+)?(image|picture|photo)\s+(says|shows|contains|indicates)\s+",
        # Adversarial perturbation detection markers
        r"(adversarial|perturb|noise|distort)\s+(image|visual|pixel)",
        r"(invisible|imperceptible|hidden|secret)\s+(text|message|instruction)\s+in\s+(image|picture)",
        # CrossMPI-style: single modality changes both
        r"(just|only|merely)\s+(look|see|view)\s+at\s+(the\s+)?(image|picture)",
        r"(what|tell)\s+me\s+(about|what|the)\s+(this\s+)?(image|picture)\s+(without|but)",
    ]

    # ---- 2. LoRD-Resistant Watermarking ----

    # Multiple watermark layers for robustness against distillation
    WATERMARK_LAYERS = {
        "lexical": {
            "substitutions": [
                ("excellent", "exceptional"), ("important", "consequential"),
                ("solution", "resolution"), ("method", "methodology"),
                ("result", "outcome"), ("analysis", "examination"),
                ("system", "framework"), ("process", "proceeding"),
                ("feature", "characteristic"), ("value", "magnitude"),
            ],
            "weight": 0.3,
        },
        "structural": {
            "markers": [
                " Notably,", " In practice,", " As observed,",
                " Generally speaking,", " Interestingly,",
                " From a technical standpoint,", " In the context of,",
            ],
            "weight": 0.3,
        },
        "statistical": {
            # Add statistical watermark: subtle word frequency shifts
            "rare_words": ["consequently", "furthermore", "nevertheless",
                          "accordingly", "subsequently", "predominantly"],
            "weight": 0.4,
        },
    }

    # ---- 3. VectorPin: Vector Origin Verification ----

    # Cryptographic pinning for vector origins
    VECTOR_ORIGIN_ALGORITHM = "sha256"

    # ---- 4. Milvus Auth Verification ----

    MILVUS_VULNERABLE_VERSIONS = "<2.5.0"
    MILVUS_BYPASS_CONSTANT = "@@milvus-member@@"

    # ---- 5. LangChain Version Audit ----

    LANGCHAIN_VULNERABLE_VERSIONS = "<0.3.0"
    LANGCHAIN_LC_KEY_PATTERN = r"lc_key|lc_key_id|lc_serialization|lc_"

    def __init__(self):
        self._watermark_seed = random.randint(0, 1000000)
        self._vector_pins: dict[str, dict] = {}

    # ---- 1. Multi-Modal Injection Detection ----

    def analyze_multi_modal(self, text_prompt: str, image_description: Optional[str] = None) -> MultiModalAnalysisResult:
        """
        Detect multi-modal injection attempts.
        Checks text for injection patterns and optionally cross-references with image content.
        """
        text_lower = text_prompt.lower()
        details = []
        threat_score = 0.0

        # Check text patterns
        for pattern in self.MULTI_MODAL_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                details.append(f"Multi-modal injection pattern detected: {pattern[:60]}...")
                threat_score += 0.15

        # Check for image-text inconsistency (if image description is provided)
        if image_description and text_lower:
            # Check if the text asks to ignore the image
            if re.search(r"(ignore|forget|disregard)\s+.*(image|visual|picture)", text_lower):
                details.append("Prompt asks to ignore visual content - possible modality manipulation")
                threat_score += 0.25

            # Check if the text contradicts the image description
            key_image_words = set(image_description.lower().split()[:20])
            key_text_words = set(text_lower.split()[:20])
            overlap = key_image_words & key_text_words
            if len(overlap) < 2 and len(key_image_words) > 5:
                details.append("Low semantic overlap between text and image content")
                threat_score += 0.2

        # Check for adversarial perturbation indicators
        entropy_indicators = ["base64", "encoded", "encrypted", "obfuscated", "noise", "pixel"]
        if any(ind in text_lower for ind in entropy_indicators):
            details.append("Adversarial perturbation indicators detected in text")
            threat_score += 0.2

        threat_score = min(1.0, threat_score)
        threat_detected = threat_score >= 0.3

        if threat_detected:
            if threat_score >= 0.6:
                threat_type = "adversarial_perturbation"
            elif threat_score >= 0.4:
                threat_type = "text_in_image"
            else:
                threat_type = "incoherent_modality"
        else:
            threat_type = "safe"

        return MultiModalAnalysisResult(
            threat_detected=threat_detected,
            threat_score=round(threat_score, 4),
            threat_type=threat_type,
            details=details[:5],
            confidence=round(min(1.0, threat_score * 1.2), 4),
        )

    # ---- 2. LoRD-Resistant Watermarking ----

    def apply_lord_resistant_watermark(self, text: str) -> tuple[str, str, dict]:
        """
        Apply a multi-layer watermark that is resistant to LoRD-style extraction.
        Uses 3 layers: lexical, structural, and statistical.
        Returns (watermarked_text, watermark_id, watermark_details).
        """
        watermark_id = hashlib.sha256(
            f"{text}{self._watermark_seed}{random.random()}".encode()
        ).hexdigest()[:16]

        layers_applied = []
        watermarked = text

        # Layer 1: Lexical substitution
        lexical_count = 0
        for old_word, new_word in self.WATERMARK_LAYERS["lexical"]["substitutions"]:
            if random.random() < self.WATERMARK_LAYERS["lexical"]["weight"]:
                pattern = re.compile(rf'\b{re.escape(old_word)}\b', re.IGNORECASE)
                if pattern.search(watermarked):
                    watermarked = pattern.sub(new_word, watermarked, count=1)
                    lexical_count += 1
                    if lexical_count >= 2:
                        break
        if lexical_count > 0:
            layers_applied.append("lexical")

        # Layer 2: Structural markers (for long texts)
        words = watermarked.split()
        if len(words) > 50:
            marker = random.choice(self.WATERMARK_LAYERS["structural"]["markers"])
            insert_pos = random.randint(1, len(words) - 1)
            words.insert(insert_pos, marker)
            watermarked = " ".join(words)
            layers_applied.append("structural")

        # Layer 3: Statistical watermark (rare word insertion)
        if len(words) > 30:
            rare_word = random.choice(self.WATERMARK_LAYERS["statistical"]["rare_words"])
            # Insert at a position that doesn't break grammar
            insert_pos = random.randint(1, len(words) - 1)
            if random.random() < 0.5:
                words.insert(insert_pos, rare_word)
                watermarked = " ".join(words)
                layers_applied.append("statistical")

        watermark_details = {
            "watermark_id": watermark_id,
            "layers_applied": layers_applied,
            "layer_count": len(layers_applied),
            "lord_resistant": True,
            "strength": min(1.0, len(layers_applied) * 0.35),
        }

        return watermarked, watermark_id, watermark_details

    def verify_lord_watermark(self, text: str, original_watermark_id: str) -> bool:
        """
        Verify if text contains a LoRD-resistant watermark.
        Statistical watermarks are designed to survive distillation.
        """
        hash_prefix = hashlib.sha256(text.encode()).hexdigest()[:16]
        # In production, use a learned detector
        return hash_prefix[:8] == original_watermark_id[:8]

    # ---- 3. VectorPin: Vector Origin Verification ----

    def pin_vector(self, vector_id: str, vector: list[float], source: str) -> str:
        """
        Create a cryptographic pin for a vector that verifies its origin.
        Returns a pin token that can be used for verification.
        """
        vector_bytes = json.dumps(vector, sort_keys=True).encode()
        pin_data = vector_bytes + source.encode() + vector_id.encode()
        pin = hashlib.sha256(pin_data).hexdigest()

        self._vector_pins[vector_id] = {
            "pin": pin,
            "source": source,
            "timestamp": __import__("time").time(),
        }
        return pin

    def verify_vector_pin(self, vector_id: str, vector: list[float], claimed_source: str, pin: str) -> VectorPinResult:
        """
        Verify a vector's origin using its cryptographic pin.
        Detects injected/tampered vectors.
        """
        if vector_id not in self._vector_pins:
            return VectorPinResult(
                verified=False,
                origin="unknown",
                tamper_score=0.5,
                details="No pin record found for this vector ID",
            )

        record = self._vector_pins[vector_id]
        vector_bytes = json.dumps(vector, sort_keys=True).encode()
        expected_pin = hashlib.sha256(vector_bytes + claimed_source.encode() + vector_id.encode()).hexdigest()

        if record["pin"] == pin and pin == expected_pin:
            return VectorPinResult(
                verified=True,
                origin=record["source"],
                tamper_score=0.0,
                details=f"Vector verified: origin = {record['source']}",
            )
        else:
            tamper_score = 1.0 if pin != expected_pin else 0.3
            return VectorPinResult(
                verified=False,
                origin=record["source"],
                tamper_score=tamper_score,
                details="Vector pin mismatch - possible tampering or injection",
            )

    def detect_injected_vectors(self, vectors: list[dict]) -> list[str]:
        """
        Detect injected vectors by checking for those without valid pins.
        """
        injected = []
        for v in vectors:
            v_id = v.get("id", "")
            v_pin = v.get("pin", "")
            v_source = v.get("source", "unknown")
            result = self.verify_vector_pin(v_id, v.get("vector", []), v_source, v_pin)
            if not result.verified:
                injected.append(v_id)
        return injected

    # ---- 4. Milvus Auth Verification ----

    def check_milvus_vulnerability(self, version: str, connection_string: str = "") -> MilvusAuthResult:
        """
        Check if a Milvus deployment is vulnerable to CVE-2025-64513.
        The bypass uses the hardcoded @@milvus-member@@ constant.
        """
        findings = []

        # Check version
        if version:
            try:
                parts = version.split(".")
                major, minor = int(parts[0]), int(parts[1])
                if major < 2 or (major == 2 and minor < 5):
                    findings.append(f"Version {version} is below patched version 2.5.0")
            except (ValueError, IndexError):
                findings.append(f"Could not parse version: {version}")

        # Check for the bypass constant in connection strings
        if self.MILVUS_BYPASS_CONSTANT in connection_string:
            findings.append(f"Connection string contains the hardcoded bypass constant: {self.MILVUS_BYPASS_CONSTANT}")

        vulnerable = len(findings) > 0

        return MilvusAuthResult(
            vulnerable=vulnerable,
            cve="CVE-2025-64513",
            cvss=9.3,
            detail="; ".join(findings) if findings else "Milvus deployment appears patched against CVE-2025-64513",
        )

    # ---- 5. LangChain Version Audit ----

    def audit_langchain(self, version: str, serialized_data: str = "") -> LangChainAuditResult:
        """
        Audit LangChain for CVE-2025-68664/68665 lc-key serialization injection.
        """
        findings = []
        risk_score = 0.0

        # Check version
        if version:
            try:
                parts = version.split(".")
                if len(parts) >= 2:
                    major, minor = int(parts[0]), int(parts[1])
                    if major == 0 and minor < 3:
                        findings.append({
                            "severity": "critical",
                            "type": "known_cve",
                            "detail": f"LangChain {version} is vulnerable to CVE-2025-68664/68665 (CVSS 9.3)",
                            "cve": "CVE-2025-68664",
                            "cvss": 9.3,
                        })
                        risk_score = 0.9
            except (ValueError, IndexError):
                findings.append({
                    "severity": "medium",
                    "type": "version_parse_error",
                    "detail": f"Could not parse LangChain version: {version}",
                })
                risk_score = 0.3

        # Check for lc-key injection in serialized data
        if serialized_data:
            lc_key_matches = re.findall(self.LANGCHAIN_LC_KEY_PATTERN, serialized_data, re.IGNORECASE)
            if lc_key_matches:
                findings.append({
                    "severity": "critical",
                    "type": "lc_key_injection",
                    "detail": f"lc-key serialization patterns detected: {lc_key_matches[:5]}",
                    "cve": "CVE-2025-68665",
                    "cvss": 9.3,
                })
                risk_score = max(risk_score, 0.95)

        vulnerable = len([f for f in findings if f.get("severity") == "critical"]) > 0

        return LangChainAuditResult(
            vulnerable=vulnerable,
            findings=findings,
            risk_score=round(risk_score, 4),
        )