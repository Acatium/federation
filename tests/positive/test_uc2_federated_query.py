"""UC-2: Federated Query with Layered Governance.

Verifies that Trino can execute queries against Redshift through the
federation layer. Trino is the governed cross-platform query engine;
Ranger enforces policy at the Trino boundary, and the source platform
enforces its own native governance underneath.
"""
import logging
from typing import Any

import pytest

logger = logging.getLogger(__name__)


class TestFederatedQuery:
    """Verify Trino can query Redshift and that the federation layer works."""

    @pytest.mark.slow
    def test_trino_query_redshift_count(self, trino_conn: Any) -> None:
        """Query Redshift through Trino and verify row count.

        The ledger_entries table in Redshift was loaded with 500K rows.
        We query through Trino's Redshift connector and verify we get data.
        """
        cursor = trino_conn.cursor()
        # The Trino catalog for Redshift is 'redshift', schema 'federation'
        # (mapped from Redshift's dev.federation schema)
        cursor.execute(
            "SELECT count(*) FROM redshift.federation.ledger_entries"
        )
        result = cursor.fetchone()
        assert result is not None, "Query returned no result"
        count = result[0]
        logger.info(
            "Trino query to redshift.federation.ledger_entries returned count=%d",
            count,
        )
        # Data contract says 500K rows loaded
        assert count > 0, (
            f"Expected rows in ledger_entries, got count={count}"
        )
        assert count >= 400_000, (
            f"Expected ~500K rows in ledger_entries, got count={count}. "
            "Data may not be fully loaded."
        )

    @pytest.mark.slow
    def test_trino_catalogs_include_redshift(self, trino_conn: Any) -> None:
        """Verify that Trino's catalog list includes the Redshift connector."""
        cursor = trino_conn.cursor()
        cursor.execute("SHOW CATALOGS")
        rows = cursor.fetchall()
        catalogs = [row[0] for row in rows]
        logger.info("Trino catalogs: %s", catalogs)
        assert "redshift" in catalogs, (
            f"Expected 'redshift' in Trino catalogs, got: {catalogs}"
        )

    @pytest.mark.slow
    def test_trino_catalogs_include_hive(self, trino_conn: Any) -> None:
        """Verify that Trino's catalog list includes the Hive/Glue connector.

        The Hive connector reads Glue-cataloged Parquet from S3.
        With the Gravitino connector, this catalog may be named 'aws_glue'
        instead of 'hive' (configurable via TRINO_HIVE_CATALOG env var).
        """
        import os
        expected_catalog = os.getenv("TRINO_HIVE_CATALOG", "hive")
        cursor = trino_conn.cursor()
        cursor.execute("SHOW CATALOGS")
        rows = cursor.fetchall()
        catalogs = [row[0] for row in rows]
        assert expected_catalog in catalogs, (
            f"Expected '{expected_catalog}' in Trino catalogs, got: {catalogs}"
        )
        logger.info(
            "Trino catalogs include '%s' (Hive/Glue connector). All catalogs: %s",
            expected_catalog, catalogs,
        )

    @pytest.mark.slow
    def test_trino_query_returns_columns(self, trino_conn: Any) -> None:
        """Verify Trino query returns expected columns from ledger_entries."""
        cursor = trino_conn.cursor()
        cursor.execute(
            "SELECT * FROM redshift.federation.ledger_entries LIMIT 1"
        )
        rows = cursor.fetchall()
        assert len(rows) == 1, "Expected exactly one row from LIMIT 1 query"
        description = cursor.description
        column_names = [d[0] for d in description]
        logger.info("Columns from ledger_entries via Trino: %s", column_names)
        # Verify key columns exist
        expected_columns = {"entry_id", "token_id", "amount", "jurisdiction"}
        found_columns = set(column_names)
        missing = expected_columns - found_columns
        assert not missing, (
            f"Missing expected columns in Trino result: {missing}. "
            f"Got: {column_names}"
        )
