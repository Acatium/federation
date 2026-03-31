"""Unit tests for the entitlement matrix report."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

import requests

from src.reports.entitlement_matrix import (
    EntitlementMatrix,
    _normalize_policy,
    _parse_source_from_labels,
    MATRIX_COLUMNS,
)

logger = logging.getLogger(__name__)


def _make_access_policy(
    name: str = "test_access",
    catalog: str = "hive",
    schema: str = "federation_demo",
    table: str = "ledger_entries",
    users: list[str] | None = None,
    groups: list[str] | None = None,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    """Build a synthetic Ranger access policy (policyType 0)."""
    return {
        "name": name,
        "policyType": 0,
        "isEnabled": True,
        "resources": {
            "catalog": {"values": [catalog]},
            "schema": {"values": [schema]},
            "table": {"values": [table]},
            "column": {"values": ["*"]},
        },
        "policyItems": [
            {
                "users": ["test_user"] if users is None else users,
                "groups": groups if groups is not None else [],
                "accesses": [{"type": "select", "isAllowed": True}],
            }
        ],
        "denyPolicyItems": [],
        "dataMaskPolicyItems": [],
        "rowFilterPolicyItems": [],
        "policyLabels": labels or ["source:lake_formation", "extraction_ts:2024-01-01T00:00:00Z"],
    }


def _make_masking_policy(
    name: str = "test_mask",
    column: str = "token_id",
    mask_type: str = "MASK_HASH",
) -> dict[str, Any]:
    """Build a synthetic Ranger masking policy (policyType 1)."""
    return {
        "name": name,
        "policyType": 1,
        "isEnabled": True,
        "resources": {
            "catalog": {"values": ["hive"]},
            "schema": {"values": ["federation_demo"]},
            "table": {"values": ["ledger_entries"]},
            "column": {"values": [column]},
        },
        "policyItems": [],
        "denyPolicyItems": [],
        "dataMaskPolicyItems": [
            {
                "users": ["analyst"],
                "groups": [],
                "dataMaskInfo": {"dataMaskType": mask_type},
                "accesses": [{"type": "select", "isAllowed": True}],
            }
        ],
        "rowFilterPolicyItems": [],
        "policyLabels": ["source:immuta", "extraction_ts:2024-01-01T00:00:00Z"],
    }


def _make_row_filter_policy(
    name: str = "test_filter",
    filter_expr: str = "region = 'US'",
) -> dict[str, Any]:
    """Build a synthetic Ranger row-filter policy (policyType 2)."""
    return {
        "name": name,
        "policyType": 2,
        "isEnabled": True,
        "resources": {
            "catalog": {"values": ["hive"]},
            "schema": {"values": ["federation_demo"]},
            "table": {"values": ["ledger_entries"]},
        },
        "policyItems": [],
        "denyPolicyItems": [],
        "dataMaskPolicyItems": [],
        "rowFilterPolicyItems": [
            {
                "users": ["analyst"],
                "groups": [],
                "rowFilterInfo": {"filterExpr": filter_expr},
                "accesses": [{"type": "select", "isAllowed": True}],
            }
        ],
        "policyLabels": ["source:immuta", "extraction_ts:2024-01-01T00:00:00Z"],
    }


class TestNormalizePolicy:
    """Tests for _normalize_policy."""

    def test_normalize_access_policy(self) -> None:
        """Access policy produces rows with correct schema."""
        policy = _make_access_policy()
        rows = _normalize_policy(policy)
        assert len(rows) >= 1
        row = rows[0]
        assert row["dataset_name"] == "hive.federation_demo.ledger_entries.*"
        assert row["principal"] == "user:test_user"
        assert row["privilege"] == "select"
        assert row["policy_type"] == "access"
        assert row["source_system"] == "lake_formation"
        assert row["extraction_timestamp"] == "2024-01-01T00:00:00Z"
        for col in MATRIX_COLUMNS:
            assert col in row
        logger.info("Access policy -> %d rows: dataset=%s, principal=%s, privilege=%s, source=%s",
                     len(rows), row["dataset_name"], row["principal"], row["privilege"], row["source_system"])

    def test_normalize_masking_policy(self) -> None:
        """Masking policy produces rows with mask type in privilege."""
        policy = _make_masking_policy()
        rows = _normalize_policy(policy)
        assert len(rows) >= 1
        privileges = {r["privilege"] for r in rows}
        assert "mask:MASK_HASH" in privileges
        assert rows[0]["policy_type"] == "masking"
        logger.info("Masking policy -> %d rows, privileges=%s", len(rows), privileges)

    def test_normalize_row_filter_policy(self) -> None:
        """Row filter policy produces rows with filter expression in privilege."""
        policy = _make_row_filter_policy(filter_expr="region = 'US'")
        rows = _normalize_policy(policy)
        assert len(rows) >= 1
        privileges = {r["privilege"] for r in rows}
        assert "filter:region = 'US'" in privileges
        assert rows[0]["policy_type"] == "row_filter"
        logger.info("Row filter policy -> %d rows, privileges=%s", len(rows), privileges)

    def test_multiple_users_and_accesses(self) -> None:
        """Multiple users and accesses produce cross-product rows."""
        policy = _make_access_policy(users=["alice", "bob"])
        policy["policyItems"][0]["accesses"] = [
            {"type": "select", "isAllowed": True},
            {"type": "insert", "isAllowed": True},
        ]
        rows = _normalize_policy(policy)
        principals = {r["principal"] for r in rows}
        privileges = {r["privilege"] for r in rows}
        assert "user:alice" in principals
        assert "user:bob" in principals
        assert "select" in privileges
        assert "insert" in privileges
        logger.info("Cross-product: %d rows, principals=%s, privileges=%s", len(rows), principals, privileges)

    def test_groups_in_principal(self) -> None:
        """Groups are prefixed with 'group:' in principal column."""
        policy = _make_access_policy(users=[], groups=["data_analysts"])
        rows = _normalize_policy(policy)
        assert rows[0]["principal"] == "group:data_analysts"
        logger.info("Group principal: %s", rows[0]["principal"])


class TestParseSourceFromLabels:
    """Tests for _parse_source_from_labels."""

    def test_standard_labels(self) -> None:
        """Standard source and extraction_ts labels are parsed."""
        source, ts = _parse_source_from_labels(
            ["source:lake_formation", "extraction_ts:2024-01-01T00:00:00Z"]
        )
        assert source == "lake_formation"
        assert ts == "2024-01-01T00:00:00Z"
        logger.info("Parsed labels: source=%s, ts=%s", source, ts)

    def test_missing_labels(self) -> None:
        """Missing labels return empty strings."""
        source, ts = _parse_source_from_labels(["governance_tier:platform_native"])
        assert source == ""
        assert ts == ""
        logger.info("Missing source/ts labels -> source='%s', ts='%s'", source, ts)

    def test_empty_labels(self) -> None:
        """Empty label list returns empty strings."""
        source, ts = _parse_source_from_labels([])
        assert source == ""
        assert ts == ""
        logger.info("Empty labels -> source='%s', ts='%s'", source, ts)

    def test_multiple_source_labels(self) -> None:
        """Last source label wins (no duplicates expected, but handled)."""
        source, ts = _parse_source_from_labels(["source:first", "source:second"])
        assert source == "second"
        logger.info("Multiple source labels -> last wins: '%s'", source)


class TestEmptyMatrix:
    """Tests for empty DataFrame with correct schema."""

    def test_empty_policies_returns_empty_dataframe(self) -> None:
        """Empty input produces DataFrame with correct columns, zero rows."""
        matrix = EntitlementMatrix()
        df = matrix.build(policies=[])
        assert df.height == 0
        assert set(df.columns) == set(MATRIX_COLUMNS)
        logger.info("Empty policies -> DataFrame with %d rows and columns %s", df.height, df.columns)

    def test_none_policies_returns_empty_on_error(self) -> None:
        """When Ranger is unreachable, returns empty DataFrame."""
        matrix = EntitlementMatrix(ranger_host="nonexistent.local")
        with patch("src.reports.entitlement_matrix.requests.get") as mock_get:
            mock_get.side_effect = requests.ConnectionError("Connection refused")
            df = matrix.build()
            assert df.height == 0
            assert set(df.columns) == set(MATRIX_COLUMNS)


class TestEntitlementMatrixBuild:
    """Tests for EntitlementMatrix.build with pre-fetched policies."""

    def test_build_with_mixed_policies(self) -> None:
        """Matrix correctly normalizes a mix of policy types."""
        policies = [
            _make_access_policy(name="access1"),
            _make_masking_policy(name="mask1"),
            _make_row_filter_policy(name="filter1"),
        ]
        matrix = EntitlementMatrix()
        df = matrix.build(policies=policies)
        assert df.height > 0
        policy_types = df["policy_type"].unique().to_list()
        assert "access" in policy_types
        assert "masking" in policy_types
        assert "row_filter" in policy_types
        logger.info("Mixed policies -> %d rows, policy_types=%s", df.height, sorted(policy_types))
