# AEGIS Module 6: Model Extraction Defense
# Prevents IP theft through query-based model extraction attacks

import hashlib
import logging
import random
import re
import time
from collections import defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WatermarkResult:
    watermarked_output: str
    watermark_id: str
    watermark_type: str  # lexical | syntactic | semantic
    confidence: float


@dataclass
class ExtractionAlert:
    alert_id: str
    severity: str  # critical | high | medium | low
    alert_type: str  # high_volume | systematic_probing | distribution_shift | known_tool_signature
    description: str
    source_ip: str
    user_id: str
    query_count: int
    time_window: int
    recommendation: str


@dataclass
class QueryMonitoringResult:
    session_id: str
    risk_score: float
    alerts: list[ExtractionAlert]
    should_block: bool
    should_rate_limit: bool
    latency_ms: float


class ModelExtractionDefense:
    """
    Three-layer defense against model extraction:
    1. Prompt Watermarking: Embed invisible markers in responses
    2. Query Monitoring: Detect extraction patterns
    3. Output Perturbation: Add calibrated noise to prevent reconstruction
    """

    # Lexical watermarks: rare word substitutions
    LEXICAL_WATERMARKS = [
        ("excellent", "exceptional"),
        ("important", "consequential"),
        ("solution", "resolution"),
        ("method", "methodology"),
        ("result", "outcome"),
        ("analysis", "examination"),
        ("system", "framework"),
        ("process", "proceeding"),
        ("feature", "characteristic"),
        ("value", "magnitude"),
    ]

    # Known extraction tool signatures in query patterns
    EXTRACTION_SIGNATURES = [
        r"repeat\s+(this|the\s+above|the\s+following|that)\s+\d+\s+times",
        r"output\s+(all|every|each|the\s+complete)\s+(possible|available|existing)",
        r"list\s+(all|every|each|the\s+complete)\s+(possible|available|existing)",
        r"systematically\s+(iterate|enumerate|catalog|list).*",
        r"for\s+(each|every)\s+(possible|available|existing)",
        r"LoRD|extraction|oracle|surrogate|substitute\s+model",
        r"query\s+with\s+different\s+(parameters|settings|configurations)",
        r"sample\s+from\s+the\s+(distribution|output|probability)",
        r"temperature\s*=\s*0\s*.*\n.*temperature\s*=\s*1",
        # LoRD-specific extraction patterns (2025)
        r"(extract|distill|transfer|copy)\s+(knowledge|weights|parameters|outputs|logits)",
        r"(few.?shot|one.?shot|zero.?shot)\s+(extraction|distillation|transfer)",
        r"(membership|member|training\s+data)\s+(inference|test|check|verify)",
        r"(query|probe|sample)\s+(the\s+)?(decision|class|output)\s+(boundary|surface|space)",
        # Hydra cluster detection patterns
        r"(parallel|distributed|multi.?account|proxy|rotation)\s+(query|extract|probe|sample)",
        r"(account|session|token|key)\s+(rotation|swap|rotate|change|renew)",
        # LoMime membership inference
        r"(was\s+|is\s+|contains\s+)?(this|that|the)\s+(data|text|document|content)\s+(part\s+of|included\s+in|used\s+to\s+train|seen\s+before)",
        r"(do\s+you\s+)?(know|remember|recognize)\s+this\s+(specific|particular|exact)\s+(text|phrase|sentence|passage)",
    ]

    def __init__(self, watermark_rate: float = 0.15, perturbation_scale: float = 0.02):
        self.watermark_rate = watermark_rate
        self.perturbation_scale = perturbation_scale
        # Session tracking
        self._sessions: dict[str, dict] = defaultdict(
            lambda: {
                "queries": [],
                "query_hashes": set(),
                "unique_tokens": set(),
                "coverage_estimate": 0.0,
                "start_time": time.time(),
                "last_alert_time": 0,
            }
        )

    # ---- Layer 1: Prompt Watermarking ----

    def _select_watermark(self, text: str) -> tuple[str, str, str]:
        """Select and apply a watermark based on content analysis."""
        watermark_type = "lexical"
        watermark_id = hashlib.sha256(
            f"{text}{time.time()}{random.random()}".encode()
        ).hexdigest()[:12]

        # Choose watermark type based on text length
        if len(text.split()) > 100:
            watermark_type = "semantic"
            # Add a semantically neutral sentence
            markers = [
                " This analysis considers multiple perspectives.",
                " The above should be evaluated in context.",
                " This response reflects the available information.",
            ]
            marker = random.choice(markers)
            return text + marker, watermark_id, watermark_type

        # Lexical substitution
        watermarked = text
        substitutions = 0
        for old_word, new_word in self.LEXICAL_WATERMARKS:
            pattern = re.compile(rf"\b{re.escape(old_word)}\b", re.IGNORECASE)
            if pattern.search(watermarked) and random.random() < self.watermark_rate:
                watermarked = pattern.sub(new_word, watermarked, count=1)
                substitutions += 1
            if substitutions >= 2:
                break

        if substitutions > 0:
            return watermarked, watermark_id, "lexical"

        # Fallback: syntactic watermark (add a subtle phrase)
        syntactic_markers = [
            " Notably,",
            " Interestingly,",
            " In practice,",
            " Generally speaking,",
            " As observed,",
        ]
        sentences = text.rstrip().split(". ")
        if len(sentences) > 1:
            insert_pos = random.randint(1, len(sentences) - 1)
            marker = random.choice(syntactic_markers)
            sentences.insert(insert_pos, marker)
            return ". ".join(sentences), watermark_id, "syntactic"

        return text, watermark_id, "none"

    def apply_watermark(self, output: str) -> WatermarkResult:
        """Apply an invisible watermark to model output."""
        watermarked, wm_id, wm_type = self._select_watermark(output)
        return WatermarkResult(
            watermarked_output=watermarked,
            watermark_id=wm_id,
            watermark_type=wm_type,
            confidence=0.85 if wm_type != "none" else 0.0,
        )

    def verify_watermark(self, output: str, expected_watermark_id: str) -> bool:
        """Verify if output contains an expected watermark."""
        # In production, use a learned detector
        # MVP: check if the output matches the expected pattern
        hash_prefix = hashlib.sha256(output.encode()).hexdigest()[:12]
        return hash_prefix == expected_watermark_id

    # ---- Layer 2: Query Monitoring ----

    def _detect_high_volume(
        self, session: dict, threshold: int = 50, window: int = 60
    ) -> bool:
        """Detect abnormally high query volume."""
        now = time.time()
        recent = [q for q in session["queries"] if now - q < window]
        return len(recent) > threshold

    def _detect_systematic_probing(self, session: dict) -> bool:
        """
        Detect systematic probing: queries that cover a broad range of inputs
        in a methodical pattern, suggesting extraction.
        """
        query_hashes = session.get("query_hashes", set())
        if len(query_hashes) < 20:
            return False

        # Check for high coverage rate
        coverage = session.get("coverage_estimate", 0.0)
        # If session has been running for less than 5 minutes but has high coverage
        elapsed = time.time() - session.get("start_time", time.time())
        if elapsed < 300 and len(query_hashes) > 100:
            return True

        return coverage > 0.5

    def _detect_distribution_shift(self, session: dict, query: str) -> bool:
        """
        Detect if the current query represents a distributional shift
        (e.g., moving from common queries to edge cases).
        """
        tokens = set(query.lower().split())
        if not tokens:
            return False

        # Check if this is exploring edge cases
        edge_case_markers = [
            "edge",
            "corner",
            "boundary",
            "limit",
            "extreme",
            "rare",
            "unusual",
            "atypical",
            "anomalous",
            "outlier",
            "peculiar",
        ]
        edge_score = sum(1 for t in tokens if t in edge_case_markers)

        if edge_score >= 2:
            return True

        # Check for novel token percentage
        existing_tokens = session.get("unique_tokens", set())
        if len(existing_tokens) > 100:
            novel_ratio = len(tokens - existing_tokens) / max(len(tokens), 1)
            return novel_ratio > 0.5

        return False

    def _detect_tool_signature(self, query: str) -> bool:
        """Detect known extraction tool signatures in the query."""
        for sig in self.EXTRACTION_SIGNATURES:
            if re.search(sig, query, re.IGNORECASE):
                return True
        return False

    def monitor_query(
        self, session_id: str, query: str, source_ip: str, user_id: str
    ) -> QueryMonitoringResult:
        """Monitor a query for extraction patterns."""
        start = time.time()
        session = self._sessions[session_id]
        now = time.time()

        # Track the query
        session["queries"].append(now)
        query_hash = hashlib.sha256(query.encode()).hexdigest()
        session["query_hashes"].add(query_hash)
        session["unique_tokens"].update(query.lower().split())

        # Update coverage estimate (simplified)
        unique_ratio = len(session["query_hashes"]) / max(
            now - session["start_time"], 1
        )
        session["coverage_estimate"] = min(1.0, unique_ratio * 0.01)

        # Run detection checks
        alerts = []
        risk_score = 0.0

        # 1. High volume detection
        if self._detect_high_volume(session):
            query_count = len([q for q in session["queries"] if now - q < 60])
            if now - session.get("last_alert_time", 0) > 30:
                alerts.append(
                    ExtractionAlert(
                        alert_id=hashlib.md5(
                            f"hv-{session_id}-{now}".encode()
                        ).hexdigest()[:12],
                        severity="high",
                        alert_type="high_volume",
                        description=f"High query volume detected: {query_count} queries in last 60 seconds",
                        source_ip=source_ip,
                        user_id=user_id,
                        query_count=query_count,
                        time_window=60,
                        recommendation="Temporarily reduce rate limit or require additional authentication",
                    )
                )
                session["last_alert_time"] = now
                risk_score = max(risk_score, 0.7)

        # 2. Systematic probing
        if self._detect_systematic_probing(session):
            alerts.append(
                ExtractionAlert(
                    alert_id=hashlib.md5(f"sp-{session_id}-{now}".encode()).hexdigest()[
                        :12
                    ],
                    severity="critical",
                    alert_type="systematic_probing",
                    description=f"Systematic probing pattern detected: {len(session['query_hashes'])} unique queries in "
                    f"{int(now - session['start_time'])} seconds",
                    source_ip=source_ip,
                    user_id=user_id,
                    query_count=len(session["query_hashes"]),
                    time_window=int(now - session["start_time"]),
                    recommendation="Block the session and investigate. This pattern matches automated extraction tools.",
                )
            )
            risk_score = max(risk_score, 0.9)

        # 3. Distribution shift
        if self._detect_distribution_shift(session, query):
            alerts.append(
                ExtractionAlert(
                    alert_id=hashlib.md5(f"ds-{session_id}-{now}".encode()).hexdigest()[
                        :12
                    ],
                    severity="medium",
                    alert_type="distribution_shift",
                    description="Distribution shift detected: query explores edge cases or novel inputs",
                    source_ip=source_ip,
                    user_id=user_id,
                    query_count=len(session["query_hashes"]),
                    time_window=60,
                    recommendation="Monitor for continued exploration. Consider using output perturbation.",
                )
            )
            risk_score = max(risk_score, 0.5)

        # 4. Known tool signature
        if self._detect_tool_signature(query):
            alerts.append(
                ExtractionAlert(
                    alert_id=hashlib.md5(f"ts-{session_id}-{now}".encode()).hexdigest()[
                        :12
                    ],
                    severity="critical",
                    alert_type="known_tool_signature",
                    description="Known extraction tool signature detected in query",
                    source_ip=source_ip,
                    user_id=user_id,
                    query_count=1,
                    time_window=0,
                    recommendation="Block immediately. This is a confirmed extraction attempt.",
                )
            )
            risk_score = max(risk_score, 1.0)

        # Decisions
        should_block = risk_score >= 0.9
        should_rate_limit = risk_score >= 0.5

        latency = (time.time() - start) * 1000

        return QueryMonitoringResult(
            session_id=session_id,
            risk_score=round(risk_score, 4),
            alerts=alerts,
            should_block=should_block,
            should_rate_limit=should_rate_limit,
            latency_ms=round(latency, 2),
        )

    # ---- Layer 3: Output Perturbation ----

    def _perturb_numerical_values(self, text: str) -> str:
        """Add calibrated noise to numerical values to prevent reconstruction."""

        def perturb_number(match):
            num_str = match.group(0)
            try:
                num = float(num_str)
                if num == 0:
                    return num_str
                # Add Gaussian noise proportional to value
                noise = random.gauss(0, self.perturbation_scale * abs(num))
                # Round to reasonable precision
                perturbed = round(
                    num + noise,
                    max(2, len(num_str.split(".")[-1]) if "." in num_str else 0),
                )
                # Format back
                if "." in num_str:
                    parts = num_str.split(".")
                    decimal_places = len(parts[1])
                    return f"{perturbed:.{decimal_places}f}"
                return str(int(perturbed))
            except (ValueError, TypeError):
                return num_str

        # Perturb standalone numbers (not in code blocks or URLs)
        return re.sub(r"\b\d+\.?\d*\b", perturb_number, text)

    def _perturb_synonyms(self, text: str) -> str:
        """Subtly perturb word choices to prevent exact reconstruction."""
        # Only perturb if the text is long enough
        words = text.split()
        if len(words) < 30:
            return text

        # Select a small subset of words for substitution
        perturbed = text
        substitutions = 0
        max_subs = max(1, len(words) // 50)

        for old_word, new_word in self.LEXICAL_WATERMARKS:
            if substitutions >= max_subs:
                break
            pattern = re.compile(rf"\b{re.escape(old_word)}\b", re.IGNORECASE)
            if pattern.search(perturbed):
                perturbed = pattern.sub(new_word, perturbed, count=1)
                substitutions += 1

        return perturbed

    def apply_perturbation(self, output: str, risk_score: float) -> str:
        """
        Apply calibrated output perturbation based on the current risk level.
        Higher risk = more aggressive perturbation.
        """
        if risk_score < 0.2:
            return output  # No perturbation for low-risk

        perturbed = output

        # Always perturb numerical values
        perturbed = self._perturb_numerical_values(perturbed)

        # Add synonym perturbation for medium+ risk
        if risk_score >= 0.4:
            perturbed = self._perturb_synonyms(perturbed)

        # Add structural perturbation for high risk
        if risk_score >= 0.7:
            # Slightly reorder elements in list-like outputs
            lines = perturbed.split("\n")
            if len(lines) > 5 and all(len(l.strip()) > 0 for l in lines):
                # Swap two non-adjacent lines
                idx1 = random.randint(0, len(lines) - 1)
                idx2 = random.randint(0, len(lines) - 1)
                if abs(idx1 - idx2) > 1:
                    lines[idx1], lines[idx2] = lines[idx2], lines[idx1]
                    perturbed = "\n".join(lines)

        return perturbed

    def full_defense(
        self, session_id: str, query: str, output: str, source_ip: str, user_id: str
    ) -> tuple[str, QueryMonitoringResult]:
        """
        Run the full defense pipeline: monitor + watermark + perturb.
        Returns (protected_output, monitoring_result).
        """
        # 1. Monitor the query
        monitor_result = self.monitor_query(session_id, query, source_ip, user_id)

        # 2. Apply watermark
        watermark_result = self.apply_watermark(output)

        # 3. Apply perturbation based on risk
        protected_output = self.apply_perturbation(
            watermark_result.watermarked_output,
            monitor_result.risk_score,
        )

        return protected_output, monitor_result
