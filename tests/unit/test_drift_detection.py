"""Unit tests for drift detection in BaseExtractor."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)


class _StubExtractor(BaseExtractor):
    """Concrete extractor for testing BaseExtractor methods."""

    def __init__(self) -> None:
        super().__init__(source_name="test_stub")

    def extract_policies(self) -> list[dict[str, Any]]:
        return []


def _make_policy(
    name: str = "test_policy",
    table: str = "ledger_entries",
    users: list[str] | None = None,
    policy_type: int = 0,
    is_enabled: bool = True,
) -> dict[str, Any]:
    """Helper to create a synthetic Ranger policy dict."""
    return {
        "name": name,
        "service": "dev_trino",
        "policyType": policy_type,
        "isEnabled": is_enabled,
        "resources": {
            "catalog": {"values": ["hive"]},
            "schema": {"values": ["federation_demo"]},
            "table": {"values": [table]},
            "column": {"values": ["*"]},
        },
        "policyItems": [
            {
                "users": users or ["test_user"],
                "groups": [],
                "accesses": [{"type": "select", "isAllowed": True}],
            }
        ],
        "denyPolicyItems": [],
        "dataMaskPolicyItems": [],
        "rowFilterPolicyItems": [],
        "policyLabels": ["source:test_stub"],
        # Volatile fields that should be ignored by hash
        "id": 42,
        "createTime": "2024-01-01T00:00:00Z",
        "updateTime": "2024-01-01T00:00:00Z",
        "version": 3,
        "guid": "abc-123",
    }


class TestComputePolicyHash:
    """Tests for _compute_policy_hash."""

    def test_deterministic(self) -> None:
        """Same policy dict produces same hash every time."""
        ext = _StubExtractor()
        policy = _make_policy()
        hash1 = ext._compute_policy_hash(policy)
        hash2 = ext._compute_policy_hash(policy)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex
        logger.info("Deterministic hash: %s (64-char SHA-256)", hash1)

    def test_ignores_volatile_fields(self) -> None:
        """Changing id, timestamps, version, guid doesn't change hash."""
        ext = _StubExtractor()
        p1 = _make_policy()
        p2 = _make_policy()
        p2["id"] = 999
        p2["createTime"] = "2099-12-31T23:59:59Z"
        p2["updateTime"] = "2099-12-31T23:59:59Z"
        p2["version"] = 100
        p2["guid"] = "xyz-789"
        h1 = ext._compute_policy_hash(p1)
        h2 = ext._compute_policy_hash(p2)
        assert h1 == h2
        logger.info("Volatile fields (id, timestamps, version, guid) ignored: hash1=%s == hash2=%s", h1[:16], h2[:16])

    def test_different_resources_different_hash(self) -> None:
        """Policies with different resources produce different hashes."""
        ext = _StubExtractor()
        p1 = _make_policy(table="ledger_entries")
        p2 = _make_policy(table="entities")
        h1 = ext._compute_policy_hash(p1)
        h2 = ext._compute_policy_hash(p2)
        assert h1 != h2
        logger.info("Different tables -> different hashes: ledger_entries=%s, entities=%s", h1[:16], h2[:16])

    def test_different_users_different_hash(self) -> None:
        """Policies with different users produce different hashes."""
        ext = _StubExtractor()
        p1 = _make_policy(users=["alice"])
        p2 = _make_policy(users=["bob"])
        h1 = ext._compute_policy_hash(p1)
        h2 = ext._compute_policy_hash(p2)
        assert h1 != h2
        logger.info("Different users -> different hashes: alice=%s, bob=%s", h1[:16], h2[:16])

    def test_different_policy_type_different_hash(self) -> None:
        """Different policyType values produce different hashes."""
        ext = _StubExtractor()
        p1 = _make_policy(policy_type=0)
        p2 = _make_policy(policy_type=1)
        h1 = ext._compute_policy_hash(p1)
        h2 = ext._compute_policy_hash(p2)
        assert h1 != h2
        logger.info("Different policyType -> different hashes: type0=%s, type1=%s", h1[:16], h2[:16])


class TestDriftDetection:
    """Tests for _detect_drift, _load_snapshot, _save_snapshot."""

    def test_no_previous_snapshot(self, tmp_path: Path) -> None:
        """First run with no prior snapshot: all policies are 'added', zero alerts."""
        ext = _StubExtractor()
        # Point snapshot dir to tmp_path
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            policies = [_make_policy(name="policy_a"), _make_policy(name="policy_b")]
            drift = ext._detect_drift(policies)
            assert sorted(drift["added"]) == ["policy_a", "policy_b"]
            assert drift["removed"] == []
            assert drift["modified"] == []
            assert drift["total_previous"] == 0
            assert drift["total_current"] == 2

    def test_no_changes(self, tmp_path: Path) -> None:
        """Same policies as snapshot: zero drift."""
        ext = _StubExtractor()
        policies = [_make_policy(name="policy_a")]
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(policies)
            drift = ext._detect_drift(policies)
            assert drift["added"] == []
            assert drift["removed"] == []
            assert drift["modified"] == []

    def test_added_policy(self, tmp_path: Path) -> None:
        """New policy appears in extraction: in 'added' list."""
        ext = _StubExtractor()
        old = [_make_policy(name="policy_a")]
        new = [_make_policy(name="policy_a"), _make_policy(name="policy_b")]
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(old)
            drift = ext._detect_drift(new)
            assert drift["added"] == ["policy_b"]
            assert drift["removed"] == []

    def test_removed_policy(self, tmp_path: Path) -> None:
        """Old policy gone from extraction: in 'removed' list."""
        ext = _StubExtractor()
        old = [_make_policy(name="policy_a"), _make_policy(name="policy_b")]
        new = [_make_policy(name="policy_a")]
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(old)
            drift = ext._detect_drift(new)
            assert drift["added"] == []
            assert drift["removed"] == ["policy_b"]

    def test_modified_policy(self, tmp_path: Path) -> None:
        """Changed policyItems: in 'modified' list."""
        ext = _StubExtractor()
        old = [_make_policy(name="policy_a", users=["alice"])]
        new = [_make_policy(name="policy_a", users=["bob"])]
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(old)
            drift = ext._detect_drift(new)
            assert drift["modified"] == ["policy_a"]

    def test_security_alert_masking_removed(self, tmp_path: Path) -> None:
        """Masking policy removed triggers security alert."""
        ext = _StubExtractor()
        old = [_make_policy(name="mask_pii_token_id", policy_type=1)]
        new: list[dict[str, Any]] = []
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(old)
            drift = ext._detect_drift(new)
            assert drift["removed"] == ["mask_pii_token_id"]
            assert any("masking removed" in a for a in drift["security_alerts"])

    def test_security_alert_deny_removed(self, tmp_path: Path) -> None:
        """Deny policy removed triggers security alert."""
        ext = _StubExtractor()
        old = [_make_policy(name="deny_restricted_access")]
        new: list[dict[str, Any]] = []
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(old)
            drift = ext._detect_drift(new)
            assert any("deny removed" in a for a in drift["security_alerts"])

    def test_save_and_load_snapshot_roundtrip(self, tmp_path: Path) -> None:
        """Save, load, verify identical."""
        ext = _StubExtractor()
        policies = [_make_policy(name="p1"), _make_policy(name="p2")]
        with patch("src.extractors.base._SNAPSHOTS_DIR", tmp_path):
            ext._save_snapshot(policies)
            loaded = ext._load_snapshot()
            assert "p1" in loaded
            assert "p2" in loaded
            assert len(loaded) == 2
            for p in policies:
                assert loaded[p["name"]] == ext._compute_policy_hash(p)
        logger.info("Snapshot roundtrip: saved %d policies, loaded %d, hashes match", len(policies), len(loaded))


class TestTransactionalAbort:
    """Tests for majority-failure abort in push_all."""

    def test_abort_on_majority_failure(self) -> None:
        """More than 50% push failures aborts remaining pushes."""
        ext = _StubExtractor()
        # Use 6 policies so abort triggers mid-batch
        policies = [_make_policy(name=f"policy_{i}") for i in range(6)]

        # Mock push_policy to fail on all but the first
        call_count = 0

        def mock_push(policy: dict[str, Any]) -> bool:
            nonlocal call_count
            call_count += 1
            return call_count == 1  # Only first succeeds

        with patch.object(ext, "push_policy", side_effect=mock_push):
            with patch.object(ext, "_ensure_ranger_principals"):
                with patch.object(ext, "_merge_by_resource", return_value=policies):
                    result = ext.push_all(policies)

        assert ext._aborted is True
        assert result == 1  # Only first policy succeeded
        # Should have stopped early — not all 6 attempted
        # With 6 total: after attempt 4, failures=3 > 6/2=3 is False.
        # After attempt 5, failures=4 > 3 is True → abort at i=4.
        assert call_count < 6
