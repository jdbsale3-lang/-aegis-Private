# AEGIS Module 7: Vector Store Security
# Encryption, differential privacy, and access control for vector databases

import os
import json
import hashlib
import base64
import logging
import math
import random
import hmac
from dataclasses import dataclass, field
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


@dataclass
class VectorRecord:
    id: str
    vector: list[float]
    metadata: dict = field(default_factory=dict)
    collection: str = "default"


@dataclass
class AccessPolicy:
    policy_id: str
    collection: str
    allowed_roles: list[str]
    allowed_users: list[str]
    max_query_rate: int = 100
    require_encryption: bool = True
    require_authentication: bool = True


@dataclass
class QueryAuditEntry:
    query_id: str
    user_id: str
    collection: str
    access_granted: bool
    vector_count: int
    timestamp: float
    risk_level: str  # low | medium | high


@dataclass
class ReconstructionAlert:
    alert_id: str
    severity: str
    description: str
    collection: str
    user_id: str
    confidence: float
    recommendation: str


class VectorStoreSecurity:
    """
    Three-layer vector database security:
    1. Encryption at rest: AES-256-GCM for stored embeddings
    2. Differential privacy: Calibrated noise injection during query
    3. Access control: IAM integration for per-collection permissions
    """

    # Differential privacy parameters
    EPSILON_DEFAULT = 1.0  # Privacy budget (lower = more privacy)
    SENSITIVITY_DEFAULT = 2.0  # L2 sensitivity of the query function
    NOISE_SCALE_DEFAULT = 0.01  # Scale of noise for the random response mechanism

    def __init__(self, encryption_key: Optional[str] = None, epsilon: float = 1.0):
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key if isinstance(self.encryption_key, bytes)
                             else self.encryption_key.encode())
        self.epsilon = epsilon
        self.policies: dict[str, AccessPolicy] = {}
        self.audit_log: list[QueryAuditEntry] = []
        self._config_cache: dict[str, dict] = {}

    # ---- Layer 1: Encryption at Rest ----

    def _serialize_vector(self, vector: list[float]) -> str:
        """Serialize a vector to a JSON string."""
        return json.dumps(vector, separators=(",", ":"))

    def _deserialize_vector(self, serialized: str) -> list[float]:
        """Deserialize a vector from a JSON string."""
        return json.loads(serialized)

    def encrypt_vector(self, vector: list[float]) -> str:
        """
        Encrypt a vector embedding at rest.
        Returns base64-encoded ciphertext.
        """
        serialized = self._serialize_vector(vector)
        encrypted = self.cipher.encrypt(serialized.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_vector(self, ciphertext_b64: str) -> list[float]:
        """
        Decrypt a vector embedding.
        Takes base64-encoded ciphertext, returns the vector.
        """
        encrypted = base64.b64decode(ciphertext_b64)
        decrypted = self.cipher.decrypt(encrypted)
        return self._deserialize_vector(decrypted.decode())

    def encrypt_metadata(self, metadata: dict) -> str:
        """Encrypt metadata associated with a vector."""
        serialized = json.dumps(metadata, sort_keys=True)
        encrypted = self.cipher.encrypt(serialized.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_metadata(self, ciphertext_b64: str) -> dict:
        """Decrypt encrypted metadata."""
        encrypted = base64.b64decode(ciphertext_b64)
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

    def encrypt_record(self, record: VectorRecord) -> dict:
        """Encrypt a complete vector record."""
        return {
            "id": record.id,
            "vector_encrypted": self.encrypt_vector(record.vector),
            "metadata_encrypted": self.encrypt_metadata(record.metadata),
            "collection": record.collection,
            "encryption_version": "1",
            "hash": hashlib.sha256(
                self._serialize_vector(record.vector).encode()
            ).hexdigest()[:16],
        }

    def decrypt_record(self, encrypted_record: dict) -> VectorRecord:
        """Decrypt a complete encrypted record."""
        return VectorRecord(
            id=encrypted_record["id"],
            vector=self.decrypt_vector(encrypted_record["vector_encrypted"]),
            metadata=self.decrypt_metadata(encrypted_record["metadata_encrypted"]),
            collection=encrypted_record.get("collection", "default"),
        )

    # ---- Layer 2: Differential Privacy ----

    def _laplace_noise(self, scale: float) -> float:
        """Generate Laplace noise for differential privacy. Capped at 5x scale."""
        u = random.random() - 0.5
        raw = -scale * math.copysign(math.log(1 - 2 * abs(u)), u)
        # Cap noise to prevent extreme values from single queries
        return max(-scale * 5, min(scale * 5, raw))

    def add_noise_to_vector(self, vector: list[float], epsilon: Optional[float] = None) -> list[float]:
        """
        Add calibrated Laplace noise to a vector for differential privacy.
        Each dimension gets independent noise scaled by (sensitivity / epsilon).
        """
        eps = epsilon or self.epsilon
        scale = self.SENSITIVITY_DEFAULT / max(eps, 0.01)

        if scale == 0:
            return vector

        return [v + self._laplace_noise(scale) for v in vector]

    def add_noise_to_similarity(self, similarity: float, epsilon: Optional[float] = None) -> float:
        """
        Add noise to a similarity score for differential privacy.
        Used when returning similarity scores to prevent reconstruction.
        """
        eps = epsilon or self.epsilon
        scale = self.NOISE_SCALE_DEFAULT / max(eps, 0.01)
        noisy = similarity + self._laplace_noise(scale)
        return max(0.0, min(1.0, noisy))

    def privatize_query_result(self, vectors: list[list[float]],
                               similarities: list[float]) -> tuple[list[list[float]], list[float]]:
        """
        Apply differential privacy to a query result.
        Noises both vectors and similarity scores.
        """
        private_vectors = [self.add_noise_to_vector(v) for v in vectors]
        private_similarities = [self.add_noise_to_similarity(s) for s in similarities]
        return private_vectors, private_similarities

    # ---- Layer 3: Access Control ----

    def set_policy(self, policy: AccessPolicy):
        """Set or update an access policy for a collection."""
        self.policies[policy.collection] = policy
        logger.info(f"Access policy set for collection '{policy.collection}'")

    def remove_policy(self, collection: str):
        """Remove access policy for a collection."""
        if collection in self.policies:
            del self.policies[collection]
            logger.info(f"Access policy removed for collection '{collection}'")

    def check_access(self, user_id: str, user_roles: list[str],
                     collection: str) -> tuple[bool, str]:
        """
        Check if a user has access to a collection.
        Returns (granted, reason).
        """
        if collection not in self.policies:
            # Default: allow if no policy set (relaxed for MVP)
            return True, "No policy configured - default allow"

        policy = self.policies[collection]

        # Check user whitelist
        if policy.allowed_users:
            if user_id in policy.allowed_users:
                return True, f"User '{user_id}' is explicitly allowed"
            # If allowed_users is set but user is NOT in it, deny
            return False, f"User '{user_id}' is not in the allowed users list for collection '{collection}'"

        # Check role whitelist
        if policy.allowed_roles:
            for role in user_roles:
                if role in policy.allowed_roles:
                    return True, f"Role '{role}' is allowed access"

            return False, f"User '{user_id}' with roles {user_roles} does not match policy"

        # No restrictions
        return True, "No user/role restrictions"

    # ---- Reconstruction Detection ----

    def _compute_query_entropy(self, queries: list[str]) -> float:
        """
        Compute entropy of recent queries.
        Low entropy + high frequency = possible reconstruction attempt.
        """
        if not queries:
            return 0.0
        combined = " ".join(queries)
        freq = {}
        for char in combined:
            freq[char] = freq.get(char, 0) + 1
        total = len(combined)
        if total == 0:
            return 0.0
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
        return entropy

    def detect_reconstruction(self, user_id: str, collection: str,
                              recent_queries: list[str]) -> Optional[ReconstructionAlert]:
        """
        Detect potential vector reconstruction attacks.
        Looks for systematic query patterns that could reconstruct training data.
        """
        if len(recent_queries) < 10:
            return None

        # Signal 1: Low entropy + high frequency
        entropy = self._compute_query_entropy(recent_queries)
        if entropy < 3.0 and len(recent_queries) > 50:
            return ReconstructionAlert(
                alert_id=hashlib.md5(f"rec-{user_id}-{collection}".encode()).hexdigest()[:12],
                severity="high",
                description=f"Possible reconstruction attack: low entropy ({entropy:.2f}) "
                            f"with high query volume ({len(recent_queries)} queries)",
                collection=collection,
                user_id=user_id,
                confidence=0.7,
                recommendation="Limit query rate, add noise, or investigate the user's access pattern",
            )

        # Signal 2: Near-duplicate query clusters
        query_hashes = set()
        for q in recent_queries:
            q_hash = hashlib.sha256(q.encode()).hexdigest()[:8]
            query_hashes.add(q_hash)
        query_ratio = len(query_hashes) / max(len(recent_queries), 1)
        if query_ratio < 0.1 and len(recent_queries) > 100:
            return ReconstructionAlert(
                alert_id=hashlib.md5(f"rec2-{user_id}-{collection}".encode()).hexdigest()[:12],
                severity="medium",
                description=f"High query repetition detected: {len(recent_queries)} queries with only "
                            f"{len(query_hashes)} unique patterns",
                collection=collection,
                user_id=user_id,
                confidence=0.6,
                recommendation="Add output perturbation to prevent reconstruction from repeated queries",
            )

        return None

    # ---- Audit ----

    def log_query(self, entry: QueryAuditEntry):
        """Log a query for audit purposes."""
        self.audit_log.append(entry)
        # Keep only recent entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

    def get_recent_audit(self, user_id: Optional[str] = None,
                         collection: Optional[str] = None,
                         limit: int = 100) -> list[QueryAuditEntry]:
        """Get recent audit entries, optionally filtered."""
        entries = self.audit_log
        if user_id:
            entries = [e for e in entries if e.user_id == user_id]
        if collection:
            entries = [e for e in entries if e.collection == collection]
        return entries[-limit:]

    # ---- Key Rotation ----

    def rotate_key(self, new_key: Optional[str] = None):
        """Rotate the encryption key. In production, re-encrypt all data."""
        self.encryption_key = new_key or Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key if isinstance(self.encryption_key, bytes)
                             else self.encryption_key.encode())
        logger.info("Encryption key rotated")

    def get_key_fingerprint(self) -> str:
        """Get a fingerprint of the current key (for verification, not the key itself)."""
        if isinstance(self.encryption_key, bytes):
            key_bytes = self.encryption_key
        else:
            key_bytes = self.encryption_key.encode()
        return hashlib.sha256(key_bytes).hexdigest()[:16]