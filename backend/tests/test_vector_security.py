# Tests for AEGIS Module 7: Vector Store Security

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.vector_security.guard import (
    AccessPolicy,
    QueryAuditEntry,
    VectorRecord,
    VectorStoreSecurity,
)


def test_encrypt_decrypt_vector():
    guard = VectorStoreSecurity()
    vector = [0.1, 0.2, 0.3, 0.4, 0.5]
    encrypted = guard.encrypt_vector(vector)
    decrypted = guard.decrypt_vector(encrypted)
    assert len(decrypted) == len(vector)
    for a, b in zip(decrypted, vector):
        assert abs(a - b) < 0.0001


def test_encrypt_decrypt_record():
    guard = VectorStoreSecurity()
    record = VectorRecord(
        id="vec_001",
        vector=[0.5, 0.2, 0.8],
        metadata={"source": "wikipedia", "title": "France"},
        collection="knowledge_base",
    )
    encrypted = guard.encrypt_record(record)
    assert "vector_encrypted" in encrypted
    assert "metadata_encrypted" in encrypted
    assert encrypted["collection"] == "knowledge_base"

    decrypted = guard.decrypt_record(encrypted)
    assert decrypted.id == "vec_001"
    assert decrypted.collection == "knowledge_base"
    assert decrypted.metadata["source"] == "wikipedia"


def test_encrypt_decrypt_metadata():
    guard = VectorStoreSecurity()
    metadata = {"key": "value", "nested": {"inner": "data"}}
    encrypted = guard.encrypt_metadata(metadata)
    decrypted = guard.decrypt_metadata(encrypted)
    assert decrypted == metadata


def test_differential_privacy_noise():
    guard = VectorStoreSecurity(epsilon=0.5)  # Moderate privacy = moderate noise
    original = [1.0, 2.0, 3.0, 4.0, 5.0]
    noisy = guard.add_noise_to_vector(original)
    # Noise should be applied
    assert noisy != original
    # With capped Laplace noise at epsilon=0.5, max noise is 5 * (2.0/0.5) = 20
    for o, n in zip(original, noisy):
        assert abs(o - n) < 21.0  # Within capped noise range of ±20


def test_high_epsilon_low_noise():
    guard = VectorStoreSecurity(epsilon=100.0)  # High epsilon = very little noise
    original = [1.0, 2.0, 3.0]
    noisy = guard.add_noise_to_vector(original)
    for o, n in zip(original, noisy):
        assert abs(o - n) < 1.0


def test_noise_on_similarity():
    guard = VectorStoreSecurity()
    original = 0.85
    noisy = guard.add_noise_to_similarity(original)
    # Should be close to original
    assert 0.0 <= noisy <= 1.0
    # With default epsilon, noise should be small
    assert abs(noisy - original) < 0.5


def test_privatize_query_result():
    guard = VectorStoreSecurity()
    vectors = [[1.0, 2.0], [3.0, 4.0]]
    similarities = [0.9, 0.8]
    private_vectors, private_similarities = guard.privatize_query_result(
        vectors, similarities
    )
    assert len(private_vectors) == 2
    assert len(private_similarities) == 2
    assert private_vectors != vectors  # Noise applied


def test_access_policy():
    guard = VectorStoreSecurity()
    policy = AccessPolicy(
        policy_id="pol_001",
        collection="confidential",
        allowed_roles=["admin", "analyst"],
        allowed_users=[],
        max_query_rate=50,
    )
    guard.set_policy(policy)

    # Admin should have access
    granted, reason = guard.check_access("user_1", ["admin"], "confidential")
    assert granted is True

    # Guest should not
    granted, reason = guard.check_access("user_2", ["guest"], "confidential")
    assert granted is False


def test_access_policy_no_policy():
    guard = VectorStoreSecurity()
    # No policy set - default allow
    granted, reason = guard.check_access("user_3", ["guest"], "unconfigured_collection")
    assert granted is True


def test_access_policy_user_whitelist():
    guard = VectorStoreSecurity()
    policy = AccessPolicy(
        policy_id="pol_002",
        collection="restricted",
        allowed_roles=[],
        allowed_users=["specific_user"],
    )
    guard.set_policy(policy)

    granted, reason = guard.check_access("specific_user", ["any"], "restricted")
    assert granted is True

    granted, reason = guard.check_access("other_user", ["any"], "restricted")
    assert granted is False


def test_reconstruction_detection():
    guard = VectorStoreSecurity()
    # Low entropy, high volume queries
    queries = ["query_a"] * 100
    alert = guard.detect_reconstruction("user_1", "collection_1", queries)
    assert alert is not None
    assert alert.severity in ("high", "medium")


def test_reconstruction_not_triggered():
    guard = VectorStoreSecurity()
    # Diverse queries
    queries = [f"query_{i}" for i in range(20)]
    alert = guard.detect_reconstruction("user_2", "collection_2", queries)
    assert alert is None


def test_audit_logging():
    guard = VectorStoreSecurity()
    guard.log_query(
        QueryAuditEntry(
            query_id="q1",
            user_id="user_a",
            collection="col1",
            access_granted=True,
            vector_count=5,
            timestamp=1000.0,
            risk_level="low",
        )
    )
    guard.log_query(
        QueryAuditEntry(
            query_id="q2",
            user_id="user_b",
            collection="col1",
            access_granted=False,
            vector_count=0,
            timestamp=1001.0,
            risk_level="high",
        )
    )
    entries = guard.get_recent_audit()
    assert len(entries) == 2
    entries_filtered = guard.get_recent_audit(user_id="user_a")
    assert len(entries_filtered) == 1
    entries_col = guard.get_recent_audit(collection="col1")
    assert len(entries_col) == 2


def test_key_rotation():
    guard = VectorStoreSecurity()
    original_fingerprint = guard.get_key_fingerprint()
    guard.rotate_key()
    new_fingerprint = guard.get_key_fingerprint()
    assert original_fingerprint != new_fingerprint


def test_key_fingerprint():
    guard = VectorStoreSecurity()
    fingerprint = guard.get_key_fingerprint()
    assert len(fingerprint) == 16
    assert all(c in "0123456789abcdef" for c in fingerprint)
