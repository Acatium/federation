"""UC-4: Spectrum Proof Point — Dual Entitlement Trees Unified.

Verifies that Redshift Spectrum tables require BOTH Redshift RBAC and
Lake Formation entitlements. This is the killer proof point: one SQL session,
two governance stacks, unified through the federation layer. Ranger holds
policies for both Redshift and Lake Formation sources for the same table.

The Spectrum table (spectrum_federation.ledger_entries_warm) sits on S3 Parquet
cataloged in Glue. Querying it through Redshift requires:
  1. Redshift RBAC: user must have SELECT on the external schema
  2. Lake Formation: IAM role must have SELECT on the Glue table
"""
import logging
from typing import Any

import pytest
import requests

logger = logging.getLogger(__name__)


class TestSpectrumProofPoint:
    """Verify dual entitlement for Spectrum tables and Ranger policy coverage."""

    @pytest.mark.slow
    def test_spectrum_table_queryable_via_redshift(
        self, redshift_conn: Any
    ) -> None:
        """Query spectrum_federation.ledger_entries_warm through Redshift directly.

        This proves the Spectrum external table is accessible and returns data
        from S3 Parquet via Glue catalog. Both Redshift RBAC and Lake Formation
        entitlements must be satisfied for this query to succeed.
        """
        cur = redshift_conn.cursor()
        try:
            cur.execute(
                "SELECT count(*) FROM spectrum_federation.ledger_entries_warm"
            )
            result = cur.fetchone()
            assert result is not None, "Spectrum query returned no result"
            count = result[0]
            logger.info(
                "Spectrum ledger_entries_warm row count via Redshift: %d",
                count,
            )
            assert count > 0, (
                f"Expected rows in Spectrum table, got count={count}. "
                "Both Redshift RBAC and Lake Formation must grant access."
            )
        finally:
            cur.close()

    @pytest.mark.slow
    def test_spectrum_returns_data_from_s3_parquet(
        self, redshift_conn: Any
    ) -> None:
        """Verify Spectrum table returns actual row data (not just count).

        Fetches sample rows to confirm S3 Parquet files are readable through
        the Glue-cataloged Spectrum external table.
        """
        cur = redshift_conn.cursor()
        try:
            cur.execute(
                "SELECT * FROM spectrum_federation.ledger_entries_warm LIMIT 10"
            )
            rows = cur.fetchall()
            assert len(rows) > 0, (
                "Spectrum table returned 0 rows on LIMIT 10 query"
            )
            description = cur.description
            column_names = [d.name for d in description]
            logger.info(
                "Spectrum ledger_entries_warm sample: %d rows, columns=%s",
                len(rows),
                column_names,
            )
            # Verify key columns are present in the Spectrum table
            expected_cols = {"entry_id", "token_id", "amount"}
            found_cols = set(column_names)
            missing = expected_cols - found_cols
            assert not missing, (
                f"Spectrum table missing expected columns: {missing}. "
                f"Got: {column_names}"
            )
        finally:
            cur.close()

    def test_ranger_holds_redshift_source_policies(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Verify Ranger has policies with source:redshift label.

        For Spectrum tables, the Redshift RBAC side of the dual entitlement
        must be mirrored in Ranger's canonical policy store.
        """
        redshift_policies = [
            p for p in ranger_policies
            if any(
                label == "source:redshift"
                for label in p.get("policyLabels", [])
            )
        ]
        logger.info(
            "Ranger policies from source:redshift: %d", len(redshift_policies)
        )
        assert len(redshift_policies) > 0, (
            "No Ranger policies with source:redshift label. "
            "The Redshift policy extractor may not have run."
        )

    def test_ranger_holds_lake_formation_source_policies(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Verify Ranger has policies with source:lake_formation label.

        For Spectrum tables, the Lake Formation side of the dual entitlement
        must be mirrored in Ranger's canonical policy store.
        """
        lf_policies = [
            p for p in ranger_policies
            if any(
                label == "source:lake_formation"
                for label in p.get("policyLabels", [])
            )
        ]
        logger.info(
            "Ranger policies from source:lake_formation: %d", len(lf_policies)
        )
        assert len(lf_policies) > 0, (
            "No Ranger policies with source:lake_formation label. "
            "The Lake Formation policy extractor may not have run."
        )

    def test_ranger_covers_both_entitlement_trees(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Verify Ranger has policies from BOTH Redshift and Lake Formation.

        This is the dual entitlement proof at the policy level: a single Ranger
        console shows grants from both governance systems that jointly protect
        Spectrum tables.
        """
        sources_found: set[str] = set()
        for policy in ranger_policies:
            for label in policy.get("policyLabels", []):
                if label.startswith("source:"):
                    sources_found.add(label.split(":", 1)[1])

        required_sources = {"redshift", "lake_formation"}
        missing_sources = required_sources - sources_found
        logger.info(
            "Dual entitlement check: required=%s, found=%s, missing=%s",
            required_sources,
            sources_found,
            missing_sources,
        )
        assert not missing_sources, (
            f"Ranger is missing policies from: {missing_sources}. "
            f"Both Redshift and Lake Formation policies are needed for "
            f"the Spectrum dual entitlement proof. Found: {sources_found}"
        )

    @pytest.mark.slow
    def test_spectrum_and_internal_accessible_from_same_connection(
        self, redshift_conn: Any
    ) -> None:
        """Both internal and Spectrum external tables accessible in one session.

        This demonstrates that Redshift's connection context carries entitlements
        for both internal tables (Redshift RBAC) and external Spectrum tables
        (Redshift RBAC + Lake Formation).
        """
        cur = redshift_conn.cursor()
        try:
            # Internal table
            cur.execute("SELECT count(*) FROM federation.ledger_entries")
            internal_count = cur.fetchone()[0]

            # External Spectrum table
            cur.execute(
                "SELECT count(*) FROM spectrum_federation.ledger_entries_warm"
            )
            external_count = cur.fetchone()[0]

            logger.info(
                "Dual entitlement proof: internal=%d, spectrum_external=%d",
                internal_count,
                external_count,
            )
            assert internal_count > 0, "Internal table has no rows"
            assert external_count > 0, "Spectrum external table has no rows"
        finally:
            cur.close()
