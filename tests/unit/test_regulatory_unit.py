"""Pure unit tests for regulatory compliance — no infrastructure required.

These tests verify that the code-level data structures, configurations, and
contracts satisfy regulatory requirements. All imports are from src.* modules.
"""

from __future__ import annotations

import logging

import pytest

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.regulatory, pytest.mark.unit]


class TestRegulatoryUnit:
    """12 pure unit tests validating regulatory properties of code artifacts."""

    # ------------------------------------------------------------------
    # 1. GDPR Art 17: PII columns cover all tables
    # ------------------------------------------------------------------

    def test_pii_columns_cover_all_tables(self) -> None:
        """GDPR Art 17: PII_COLUMNS keys must equal DEMO_TABLES."""
        from src.extractors.base import DEMO_TABLES, PII_COLUMNS

        assert set(PII_COLUMNS.keys()) == set(DEMO_TABLES), (
            f"PII_COLUMNS tables {set(PII_COLUMNS.keys())} != "
            f"DEMO_TABLES {set(DEMO_TABLES)}"
        )
        logger.info("PII columns cover all %d tables: %s", len(DEMO_TABLES), sorted(DEMO_TABLES))

    # ------------------------------------------------------------------
    # 2. BCBS 239 P5: Sync tiers ordered
    # ------------------------------------------------------------------

    def test_sync_tiers_ordered(self) -> None:
        """BCBS 239 P5: Tier 2 syncs faster than Tier 1, Tier 1 faster than default."""
        from src.sync.config import SyncConfig

        config = SyncConfig()
        assert config.tier2_interval_seconds < config.tier1_interval_seconds
        assert config.tier1_interval_seconds < config.default_interval_seconds
        logger.info("Sync tier ordering: tier2=%ds < tier1=%ds < default=%ds",
                     config.tier2_interval_seconds, config.tier1_interval_seconds,
                     config.default_interval_seconds)

    # ------------------------------------------------------------------
    # 3. BCBS 239 P4: Source priority complete
    # ------------------------------------------------------------------

    def test_source_priority_complete(self) -> None:
        """BCBS 239 P4: All 8 extraction sources have priority assignments."""
        from src.sync.config import DEFAULT_SOURCE_PRIORITY

        expected_sources = {
            "immuta", "lake_formation", "redshift", "snowflake",
            "unity_catalog", "glue_iam", "gap_fill", "bedrock",
        }
        actual_sources = set(DEFAULT_SOURCE_PRIORITY.keys())
        assert expected_sources == actual_sources
        logger.info("All %d extraction sources have priorities: %s", len(actual_sources), DEFAULT_SOURCE_PRIORITY)

    # ------------------------------------------------------------------
    # 4. BCBS 239 P3: Deterministic seed
    # ------------------------------------------------------------------

    def test_deterministic_seed(self) -> None:
        """BCBS 239 P3: DATA_SEED must be 42 for reproducible data generation."""
        from src.utils.config import DATA_SEED

        assert DATA_SEED == 42
        logger.info("DATA_SEED=%d (deterministic generation confirmed)", DATA_SEED)

    # ------------------------------------------------------------------
    # 5. BCBS 239 P4: Schema definitions complete
    # ------------------------------------------------------------------

    def test_schema_definitions_complete(self) -> None:
        """BCBS 239 P4: All 4 table schemas have >=4 columns with name and sql_type."""
        from src.loaders.schemas import (
            COUNTERPARTY_REF_COLUMNS,
            ENTITIES_COLUMNS,
            LEDGER_ENTRIES_COLUMNS,
            RISK_SIGNALS_COLUMNS,
        )

        schemas = {
            "ledger_entries": LEDGER_ENTRIES_COLUMNS,
            "entities": ENTITIES_COLUMNS,
            "risk_signals": RISK_SIGNALS_COLUMNS,
            "counterparty_ref": COUNTERPARTY_REF_COLUMNS,
        }

        for table_name, columns in schemas.items():
            assert len(columns) >= 4
            for col in columns:
                assert col.name
                assert col.sql_type
            logger.info("Schema '%s': %d columns verified", table_name, len(columns))

    # ------------------------------------------------------------------
    # 6. Cross-regulation: PII columns match schemas
    # ------------------------------------------------------------------

    def test_pii_columns_match_schemas(self) -> None:
        """PII column names must be a subset of their table's schema column names."""
        from src.extractors.base import PII_COLUMNS
        from src.loaders.schemas import (
            COUNTERPARTY_REF_COLUMNS,
            ENTITIES_COLUMNS,
            LEDGER_ENTRIES_COLUMNS,
            RISK_SIGNALS_COLUMNS,
        )

        schema_map = {
            "ledger_entries": LEDGER_ENTRIES_COLUMNS,
            "entities": ENTITIES_COLUMNS,
            "risk_signals": RISK_SIGNALS_COLUMNS,
            "counterparty_ref": COUNTERPARTY_REF_COLUMNS,
        }

        for table_name, pii_cols in PII_COLUMNS.items():
            schema_cols = schema_map.get(table_name)
            assert schema_cols is not None
            schema_col_names = {c.name for c in schema_cols}
            pii_set = set(pii_cols)
            extra = pii_set - schema_col_names
            assert not extra
            logger.info("PII columns for '%s': %s (all in schema)", table_name, sorted(pii_cols))

    # ------------------------------------------------------------------
    # 7. DORA Art 28: Extractor source names unique
    # ------------------------------------------------------------------

    def test_extractor_source_names_unique(self) -> None:
        """DORA Art 28: All 8 extractors have distinct source_names."""
        from src.extractors import (
            BedrockExtractor,
            GlueIamExtractor,
            IcebergGapFillExtractor,
            ImmutaExtractor,
            LakeFormationExtractor,
            RedshiftExtractor,
            SnowflakeExtractor,
            UnityCatalogExtractor,
        )

        extractors = [
            ImmutaExtractor(), LakeFormationExtractor(), GlueIamExtractor(),
            RedshiftExtractor(), SnowflakeExtractor(), UnityCatalogExtractor(),
            IcebergGapFillExtractor(), BedrockExtractor(),
        ]

        source_names = [e.source_name for e in extractors]
        assert len(source_names) == 8
        assert len(set(source_names)) == len(source_names)
        logger.info("8 unique extractor source_names: %s", source_names)

    # ------------------------------------------------------------------
    # 8. DORA Art 30: Matrix columns vendor-neutral
    # ------------------------------------------------------------------

    def test_matrix_columns_vendor_neutral(self) -> None:
        """DORA Art 30: Entitlement matrix column names must be vendor-neutral."""
        from src.reports.entitlement_matrix import MATRIX_COLUMNS

        vendor_terms = {"ranger", "trino", "aws"}
        for col in MATRIX_COLUMNS:
            col_lower = col.lower()
            for term in vendor_terms:
                assert term not in col_lower
        logger.info("Matrix columns (all vendor-neutral): %s", MATRIX_COLUMNS)

    # ------------------------------------------------------------------
    # 9. DORA Art 15: Policy hash deterministic
    # ------------------------------------------------------------------

    def test_policy_hash_deterministic(self) -> None:
        """DORA Art 15: Same policy produces the same hash every time."""
        from src.extractors.base import BaseExtractor

        policy = {
            "resources": {
                "catalog": {"values": ["redshift"]},
                "schema": {"values": ["federation"]},
                "table": {"values": ["ledger_entries"]},
            },
            "policyItems": [
                {
                    "users": ["test_user"],
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ],
            "policyType": 0,
            "isEnabled": True,
        }

        hash1 = BaseExtractor._compute_policy_hash(policy)
        hash2 = BaseExtractor._compute_policy_hash(policy)
        assert hash1 == hash2
        assert len(hash1) == 64
        logger.info("Policy hash deterministic: %s (SHA-256, 64 chars)", hash1)

    # ------------------------------------------------------------------
    # 10. GDPR: Immuta policies have purposes
    # ------------------------------------------------------------------

    def test_immuta_policies_have_purposes(self) -> None:
        """GDPR: Every Immuta policy must have a non-empty purpose."""
        from src.mocks.immuta_mock import POLICIES

        purposes = []
        for policy in POLICIES:
            purpose = policy.get("purpose", "")
            assert purpose
            purposes.append(purpose)
        logger.info("All %d Immuta policies have purposes: %s", len(POLICIES), purposes)

    # ------------------------------------------------------------------
    # 11. SOX: Immuta permissions segregation
    # ------------------------------------------------------------------

    def test_immuta_permissions_segregation(self) -> None:
        """SOX: At least 4 distinct groups in Immuta PERMISSIONS for SoD."""
        from src.mocks.immuta_mock import PERMISSIONS

        groups = {p.get("group", "") for p in PERMISSIONS if p.get("group")}
        assert len(groups) >= 4
        logger.info("Segregation of duties: %d distinct groups: %s", len(groups), sorted(groups))

    # ------------------------------------------------------------------
    # 12. EU AI Act Art 12: Bedrock models have ARNs
    # ------------------------------------------------------------------

    def test_bedrock_models_have_arns(self) -> None:
        """EU AI Act Art 12: All Bedrock model version URIs start with arn:aws:bedrock:."""
        from src.models.bedrock_catalog import BEDROCK_MODELS

        for model in BEDROCK_MODELS:
            for version in model.get("versions", []):
                uri = version.get("uri", "")
                assert uri.startswith("arn:aws:bedrock:")
        model_names = [m["name"] for m in BEDROCK_MODELS]
        logger.info("All %d Bedrock models have valid ARN URIs: %s", len(BEDROCK_MODELS), model_names)
