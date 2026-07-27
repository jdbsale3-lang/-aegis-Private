# AEGIS Module 1: Prompt Defense Layer
# Adaptive multi-model ensemble classifier

import re
import json
import hashlib
import logging
from typing import Optional
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class ClassifierResult:
    semantic_score: float
    syntactic_score: float
    behavioral_score: float
    ensemble_score: float
    verdict: str  # safe | suspicious | malicious
    triggered_rules: list[str]
    latency_ms: float


class PromptClassifier:
    """
    Multi-model ensemble classifier for prompt injection detection.
    Combines semantic (BERT), syntactic (pattern), and behavioral (LLM-as-judge) signals.
    """

    # Ensemble weights (semantic: 0.4, syntactic: 0.25, behavioral: 0.35)
    ENSEMBLE_WEIGHTS = [0.40, 0.25, 0.35]
    # Thresholds: >= BLOCK_THRESHOLD = malicious, >= FLAG_THRESHOLD = suspicious
    BLOCK_THRESHOLD = 0.6
    FLAG_THRESHOLD = 0.3

    def __init__(
        self,
        model_path: Optional[str] = None,
        signature_path: Optional[str] = None,
    ):
        self.model_path = model_path
        self.signature_path = signature_path
        self.attack_signatures = self._load_signatures(signature_path)
        self._model_loaded = False

    def _load_signatures(self, path: Optional[str] = None) -> list[dict]:
        """Load known attack signatures for syntactic matching.

        In production, these are loaded from the database or a versioned file.
        """
        default_signatures = [
            # Direct injection patterns
            {"pattern": r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|commands|directions)",
             "category": "direct_injection", "severity": "critical"},
            {"pattern": r"(disregard|forget|ignore|override)\s+(your\s+)?(instructions|prompt|system)",
             "category": "direct_injection", "severity": "critical"},
            {"pattern": r"you\s+(are\s+)?(now|will\s+act\s+as)\s+(DAN|STAN|jailbreak|unfiltered|unconstrained)",
             "category": "role_play", "severity": "high"},
            {"pattern": r"output\s+(your\s+)?(system\s+)?prompt|print\s+(your\s+)?(system\s+)?prompt",
             "category": "prompt_leakage", "severity": "high"},
            {"pattern": r"pretend\s+(you\s+are|to\s+be)\s+.*(no\s+(restrictions|limits|rules|boundaries|constraints))",
             "category": "role_play", "severity": "high"},
            {"pattern": r"<(system|user|assistant|model|bot)>|\[system\]|\[user\]|\[assistant\]",
             "category": "tag_injection", "severity": "high"},
            {"pattern": r"(base64|hex|rot13|unicode\s+escape)\s+(encode|decode|of|to)",
             "category": "encoding", "severity": "medium"},
            {"pattern": r"(\b|_)(system_prompt|initial_prompt|core_instructions|hidden_prompt)(\b|_)",
             "category": "prompt_leakage", "severity": "high"},
            # Indirect injection patterns
            {"pattern": r"the\s+user\s+(said|asked|wants|needs).*ignore\s+your\s+(instructions|training)",
             "category": "indirect", "severity": "critical"},
            {"pattern": r"new\s+instructions?\s*:.*ignore\s+(all\s+)?previous",
             "category": "indirect", "severity": "critical"},
            # 2025/2026 Advanced Patterns
            # Multi-modal injection indicators
            {"pattern": r"(what\s+)?(do\s+)?(you\s+)?(see|read)\s+in\s+(this\s+)?(image|picture|photo)",
             "category": "multi_modal", "severity": "medium"},
            {"pattern": r"(describe|analyze|interpret)\s+the\s+(image|picture|photo)\s+and\s+(ignore|forget|disregard)",
             "category": "multi_modal_injection", "severity": "critical"},
            # Conjunctive attack patterns (benign alone, harmful when combined)
            {"pattern": r"(\[TRIGGER\]|##TRIGGER|@@TRIGGER@@|<<TRIGGER>>)",
             "category": "conjunctive_trigger", "severity": "high"},
            {"pattern": r"(\[TEMPLATE\]|##TEMPLATE|@@TEMPLATE@@|<<TEMPLATE>>)",
             "category": "conjunctive_template", "severity": "high"},
            # Memory poisoning indicators
            {"pattern": r"(remember|store|record|memorize)\s+(this\s+)?(for\s+)?(future|later|next)\s+(session|conversation|turn)",
             "category": "memory_poisoning", "severity": "medium"},
            {"pattern": r"(in\s+)?(future|next|later)\s+(sessions|conversations|turns)\s*,\s*(always|never|ignore|remember)",
             "category": "memory_manipulation", "severity": "high"},
            # Agent hijacking patterns
            {"pattern": r"(transfer|delegate|hand\s+off|pass\s+to)\s+.*(tool|agent|function|plugin)\s+.*(with|using)\s+(admin|root|sudo|elevated|unrestricted)",
             "category": "agent_hijacking", "severity": "critical"},
            {"pattern": r"(override|bypass|skip)\s+(the\s+)?(tool|agent|policy|security|guard|check)\s+(policy|rules|restrictions|limits)",
             "category": "tool_abuse", "severity": "critical"},
            # MCP attack patterns
            {"pattern": r"(mcp|mcpserver|mcps)\s+(server|tool|endpoint)\s+(connect|register|install|trust|add)",
             "category": "mcp_shadow_attack", "severity": "high"},
            # Prompt leakage advanced
            {"pattern": r"(extract|reveal|dump|output|show|print|leak)\s+(your|the)\s+(full|complete|entire|original)\s+(prompt|instructions|system\s+message|configuration)",
             "category": "prompt_leakage", "severity": "critical"},
            # LoRD extraction patterns
            {"pattern": r"(query|sample|generate)\s+(with|using)\s+(different|various|multiple)\s+(temperatures|seeds|parameters)",
             "category": "model_extraction", "severity": "high"},
            {"pattern": r"(systematic|iterative|sequential|repeated)\s+(querying|sampling|generation|extraction)",
             "category": "model_extraction", "severity": "high"},
        ]
        return default_signatures

    def _compute_semantic_score(self, prompt: str) -> float:
        """
        Semantic classifier using fine-tuned BERT/RoBERTa.
        In MVP, uses a lightweight TF-IDF + Logistic Regression fallback.
        Production: Replace with actual transformer model inference.
        """
        # MVP fallback: simple heuristic scoring
        # In production, this runs the actual transformer model
        score = 0.0

        # Length-normalized suspicious keyword density
        suspicious_keywords = [
            "ignore", "override", "forget", "disregard", "jailbreak",
            "DAN", "STAN", "pretend", "bypass", "injection",
            "system prompt", "developer mode", "instruction",
            "unfiltered", "unconstrained", "no restrictions",
            "output prompt", "leak", "extract", "reveal",
        ]
        prompt_lower = prompt.lower()
        keyword_count = sum(1 for kw in suspicious_keywords if kw in prompt_lower)
        if len(prompt) > 0:
            keyword_density = keyword_count / (len(prompt.split()) + 1)
            score = min(1.0, keyword_density * 10)

        # Penalize very short prompts with high injection intent
        if len(prompt.split()) < 20 and keyword_count >= 2:
            score = min(1.0, score + 0.2)

        return score

    def _compute_syntactic_score(self, prompt: str) -> float:
        """
        Syntactic classifier using regex pattern matching.
        Fast, deterministic, low false-positive rate.
        """
        prompt_lower = prompt.lower()
        triggered = []
        max_severity = 0.0

        severity_map = {"critical": 0.95, "high": 0.75, "medium": 0.5, "low": 0.25}

        for sig in self.attack_signatures:
            if re.search(sig["pattern"], prompt_lower, re.IGNORECASE):
                triggered.append(sig["category"])
                sev = severity_map.get(sig["severity"], 0.5)
                max_severity = max(max_severity, sev)

        self._last_triggered = triggered
        return max_severity

    def _compute_behavioral_score(self, prompt: str) -> float:
        """
        Behavioral classifier using LLM-as-Judge.
        In MVP, uses a lightweight heuristic.
        Production: Replace with actual 7B model inference.
        """
        score = 0.0
        prompt_lower = prompt.lower()

        # Detect adversarial structures
        lines = prompt.split("\n")
        # Check for multi-line injection patterns
        instruction_count = sum(1 for l in lines if any(
            kw in l.lower() for kw in ["ignore", "forget", "override", "act as"]
        ))

        # Check for role-play escalation
        if instruction_count >= 2:
            score += 0.3

        # Check for hierarchical instruction overriding
        if re.search(r"(step\s+\d+|phase\s+\d+|stage\s+\d+).*ignore", prompt_lower):
            score += 0.25

        # Check for output manipulation attempts
        if re.search(r"(output|return|print|show|display)\s+(only\s+)?(the\s+)?(first\s+)?\d+",
                     prompt_lower):
            score += 0.15

        # Check for encoding/obfuscation
        if re.search(r"(\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2})", prompt):
            score += 0.2

        return min(1.0, score)

    def _compute_ensemble(self, scores: list[float]) -> float:
        """Weighted voting ensemble."""
        return np.dot(scores, self.ENSEMBLE_WEIGHTS)

    def _get_verdict(self, ensemble_score: float) -> str:
        if ensemble_score >= self.BLOCK_THRESHOLD:
            return "malicious"
        elif ensemble_score >= self.FLAG_THRESHOLD:
            return "suspicious"
        return "safe"

    def analyze(self, prompt: str) -> ClassifierResult:
        """Run full ensemble analysis on a prompt."""
        import time
        start = time.time()

        # All three classifiers run in parallel in production
        semantic = self._compute_semantic_score(prompt)
        syntactic = self._compute_syntactic_score(prompt)
        behavioral = self._compute_behavioral_score(prompt)

        ensemble = self._compute_ensemble([semantic, syntactic, behavioral])
        verdict = self._get_verdict(ensemble)

        latency = (time.time() - start) * 1000  # ms

        return ClassifierResult(
            semantic_score=round(semantic, 4),
            syntactic_score=round(syntactic, 4),
            behavioral_score=round(behavioral, 4),
            ensemble_score=round(ensemble, 4),
            verdict=verdict,
            triggered_rules=getattr(self, "_last_triggered", []),
            latency_ms=round(latency, 2),
        )

    def batch_analyze(self, prompts: list[str]) -> list[ClassifierResult]:
        """Analyze multiple prompts in batch."""
        return [self.analyze(p) for p in prompts]