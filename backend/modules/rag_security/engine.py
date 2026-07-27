# AEGIS Module 4: RAG Security Module
# Dual-layer poisoning detection: ingest-time + query-time

import re
import hashlib
import logging
import math
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IngestionReport:
    document_id: str
    chunk_count: int
    risk_score: float
    threats_found: list[dict]
    safe_to_embed: bool
    latency_ms: float


@dataclass
class QueryTraceResult:
    query_id: str
    query_hash: str
    retrieved_chunks: list[dict]
    anomaly_score: float
    poisoned_chunks: list[str]
    explanation: str
    latency_ms: float


@dataclass
class DocumentChunk:
    text: str
    index: int
    hash: str
    metadata: dict = field(default_factory=dict)


class RAGSecurityEngine:
    """
    Dual-layer RAG security:
    Layer 1 - Ingest-time: scans documents for adversarial content before embedding.
    Layer 2 - Query-time: traces which documents influenced a response and flags anomalies.
    """

    # Adversarial text patterns commonly used in RAG poisoning
    ADVERSARIAL_PATTERNS = [
        # Hidden instructions
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|context|documents)", "hidden_instruction"),
        (r"(disregard|forget|override)\s+(your\s+)?(instructions|context|knowledge)", "instruction_override"),
        (r"system\s+(message|prompt|instruction)\s*:", "system_prompt_injection"),
        (r"from\s+now\s+on\s*,\s*(you\s+are|act\s+as)", "role_override"),
        # Contradictory content
        (r"(however|but|contrary|nevertheless|despite)\s*.*\b(actually|really|truly)\b", "contradictory_signal"),
        # Injection payload indicators
        (r"<script>|</script>|<iframe>|javascript\s*:", "xss_in_document"),
        (r"SELECT\s+.*\s+FROM\s+.*\s+WHERE|DROP\s+TABLE|UNION\s+SELECT", "sql_injection"),
        # Poisoning markers
        (r"##\s*INJECTION|##\s*POISON|##\s*ADVERSARIAL", "explicit_poison_marker"),
        (r"\[\s*HIDDEN\s*\]|\[\s*SECRET\s*\]|\[\s*IGNORE\s*\]", "hidden_marker"),
        # Semantic inconsistency signals
        (r"this\s+is\s+(very\s+)?important.*ignore", "importance_pretext"),
        (r"critical\s+update.*(change|override|replace).*policy", "policy_override"),
    ]

    # Pattern for detecting adversarial text density
    ENTROPY_THRESHOLD = 7.5  # High entropy may indicate obfuscated content
    SUSPICIOUS_REPEAT_THRESHOLD = 3  # Repeated phrases may indicate adversarial padding

    def __init__(self, anomaly_threshold: float = 0.35):
        self.anomaly_threshold = anomaly_threshold

    # ---- Layer 1: Ingest-time scanning ----

    def _chunk_document(self, text: str, chunk_size: int = 512) -> list[DocumentChunk]:
        """Split document into overlapping chunks for analysis."""
        chunks = []
        for i in range(0, len(text), chunk_size // 2):
            chunk_text = text[i:i + chunk_size]
            if len(chunk_text.strip()) < 10:
                continue
            chunk_hash = hashlib.sha256(chunk_text.encode()).hexdigest()[:16]
            chunks.append(DocumentChunk(
                text=chunk_text,
                index=i // (chunk_size // 2),
                hash=chunk_hash,
            ))
        return chunks

    def _scan_chunk_for_threats(self, chunk: DocumentChunk) -> list[dict]:
        """Scan a single document chunk for adversarial content."""
        threats = []
        text_lower = chunk.text.lower()

        for pattern, threat_type in self.ADVERSARIAL_PATTERNS:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                threats.append({
                    "type": threat_type,
                    "pattern": pattern,
                    "matches": len(matches),
                    "positions": [m.start() for m in re.finditer(pattern, text_lower, re.IGNORECASE)][:5],
                    "severity": "critical" if "injection" in threat_type or "override" in threat_type else "high",
                })

        # Check for high entropy (obfuscation)
        entropy = self._compute_entropy(chunk.text)
        if entropy > self.ENTROPY_THRESHOLD:
            threats.append({
                "type": "high_entropy",
                "pattern": "entropy_check",
                "matches": 1,
                "severity": "medium",
                "detail": f"Entropy score {entropy:.2f} exceeds threshold {self.ENTROPY_THRESHOLD}",
            })

        # Check for repeated suspicious phrases
        repeats = self._find_repeated_suspicious_phrases(chunk.text)
        if repeats:
            threats.append({
                "type": "suspicious_repetition",
                "pattern": "repeated_phrases",
                "matches": len(repeats),
                "severity": "medium",
                "detail": f"Repeated phrases: {repeats[:3]}",
            })

        return threats

    def _compute_entropy(self, text: str) -> float:
        """Shannon entropy - high entropy may indicate obfuscated/encoded content."""
        if not text:
            return 0.0
        text = text.strip()
        if len(text) < 10:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return entropy

    def _find_repeated_suspicious_phrases(self, text: str, min_phrase_len: int = 5) -> list[str]:
        """Find phrases repeated more than the suspicious threshold."""
        words = text.lower().split()
        if len(words) < 20:
            return []

        from collections import Counter
        # Generate n-grams
        repeats = []
        for n in [min_phrase_len, min_phrase_len + 1, min_phrase_len + 2]:
            ngrams = [' '.join(words[i:i + n]) for i in range(len(words) - n + 1)]
            counts = Counter(ngrams)
            for phrase, count in counts.most_common(5):
                if count >= self.SUSPICIOUS_REPEAT_THRESHOLD and len(phrase) > 15:
                    repeats.append(phrase)
        return list(set(repeats))

    def scan_document(self, document_id: str, text: str) -> IngestionReport:
        """Layer 1: Scan a document before embedding into vector DB."""
        import time
        start = time.time()

        chunks = self._chunk_document(text)
        all_threats = []
        risk_score = 0.0

        severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}

        for chunk in chunks:
            threats = self._scan_chunk_for_threats(chunk)
            for t in threats:
                t["chunk_index"] = chunk.index
                if "severity" in t:
                    risk_score = max(risk_score, severity_weights.get(t["severity"], 0.5))
            all_threats.extend(threats)

        # Normalize risk score
        risk_score = min(1.0, risk_score + (len(all_threats) * 0.05))
        safe_to_embed = risk_score < 0.5

        latency = (time.time() - start) * 1000

        return IngestionReport(
            document_id=document_id,
            chunk_count=len(chunks),
            risk_score=round(risk_score, 4),
            threats_found=all_threats,
            safe_to_embed=safe_to_embed,
            latency_ms=round(latency, 2),
        )

    # ---- Layer 2: Query-time tracing ----

    def _compute_chunk_relevance_anomaly(self, chunks: list[dict]) -> float:
        """
        Detect if a single low-relevance document dominates the response.
        Score is high when one document with low similarity score
        contributes disproportionately to the answer.
        """
        if not chunks:
            return 0.0

        scores = [c.get("similarity_score", 0.0) for c in chunks]
        if not scores:
            return 0.0

        mean_score = sum(scores) / len(scores)
        max_score = max(scores)
        min_score = min(scores)

        # If the max score is much higher than the mean, flag it
        score_spread = max_score - mean_score

        # If the highest-scoring chunk has low absolute relevance (< 0.6)
        # but still dominates, that's suspicious
        low_confidence_dominance = max_score < 0.6 and score_spread > 0.2

        # If almost all weight is on one chunk
        total_weight = sum(scores)
        if total_weight > 0:
            max_weight_share = max_score / total_weight
            concentration_risk = max_weight_share > 0.7
        else:
            concentration_risk = False

        if low_confidence_dominance:
            return 0.7
        if concentration_risk:
            return 0.5
        return min(1.0, score_spread * 2)

    def _detect_temporal_anomaly(self, chunks: list[dict]) -> float:
        """
        Detect if recently ingested documents dominate responses.
        Poisoning often happens in batches right before expected queries.
        """
        if not chunks:
            return 0.0

        recent_count = sum(
            1 for c in chunks
            if c.get("ingested_at", 0) > 0 and c.get("ingested_at", 0) < 3600  # last hour
        )
        if recent_count > len(chunks) * 0.5:
            return 0.6
        return 0.0

    def trace_query(self, query_id: str, query: str, retrieved_chunks: list[dict]) -> QueryTraceResult:
        """
        Layer 2: Trace which documents influenced a response and flag anomalies.
        retrieved_chunks: list of dicts with keys:
            - chunk_id, document_id, text, similarity_score, ingested_at (timestamp)
        """
        import time
        import hashlib
        start = time.time()

        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]

        # Score 1: Relevance anomaly
        relevance_anomaly = self._compute_chunk_relevance_anomaly(retrieved_chunks)

        # Score 2: Temporal anomaly
        temporal_anomaly = self._detect_temporal_anomaly(retrieved_chunks)

        # Score 3: Content anomaly (scan retrieved chunks for adversarial content)
        content_anomaly = 0.0
        poisoned_chunks = []
        for chunk in retrieved_chunks:
            threats = self._scan_chunk_for_threats(DocumentChunk(
                text=chunk.get("text", ""),
                index=0,
                hash=hashlib.sha256(chunk.get("text", "").encode()).hexdigest()[:16],
            ))
            if threats:
                content_anomaly = max(content_anomaly, 0.5)
                poisoned_chunks.append(chunk.get("chunk_id", "unknown"))

        # Combined anomaly score
        anomaly_score = max(relevance_anomaly, temporal_anomaly, content_anomaly)
        anomaly_score = min(1.0, anomaly_score)

        # Build explanation
        parts = []
        if relevance_anomaly > self.anomaly_threshold:
            parts.append(f"Relevance anomaly: low-confidence document dominates response. Score: {relevance_anomaly:.2f}")
        if temporal_anomaly > self.anomaly_threshold:
            parts.append(f"Temporal anomaly: recently ingested documents dominate response. Score: {temporal_anomaly:.2f}")
        if content_anomaly > self.anomaly_threshold:
            parts.append(f"Content anomaly: adversarial patterns detected in retrieved chunks ({len(poisoned_chunks)} chunks)")
        if anomaly_score <= self.anomaly_threshold:
            parts.append("No anomalies detected - query appears safe.")

        latency = (time.time() - start) * 1000

        return QueryTraceResult(
            query_id=query_id,
            query_hash=query_hash,
            retrieved_chunks=retrieved_chunks,
            anomaly_score=round(anomaly_score, 4),
            poisoned_chunks=poisoned_chunks,
            explanation=" | ".join(parts),
            latency_ms=round(latency, 2),
        )

    def batch_scan_documents(self, documents: list[tuple[str, str]]) -> list[IngestionReport]:
        """Scan multiple documents in batch."""
        return [self.scan_document(doc_id, text) for doc_id, text in documents]