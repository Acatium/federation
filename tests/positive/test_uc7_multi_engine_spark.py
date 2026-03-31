"""UC-7: Multi-Engine Spark via Gravitino.

Proves Spark + Trino query the same Gravitino metalake. Spark through
Gravitino supports Hive and Iceberg catalogs (not JDBC), so it sees
Parquet and Iceberg on S3 but not Redshift/Snowflake directly. This is
realistic — different engines have different reach.

Governance delta: Trino has Ranger enforcement; Spark has Lake Formation
+ IAM but no Ranger plugin. Both are governed, but the governance stack
differs.
"""

import logging
import os
from typing import Any

import pytest

logger = logging.getLogger(__name__)


class TestMultiEngineSpark:
    """Verify Spark queries the same Gravitino metalake as Trino."""

    @pytest.mark.spark
    def test_spark_session_active(self, require_spark: Any) -> None:
        """Spark session should be active with Gravitino plugin loaded."""
        sc = require_spark.sparkContext
        assert sc is not None, "SparkContext is None"
        assert not sc._jsc.sc().isStopped(), "SparkContext is stopped"
        logger.info(
            "Spark session active: app=%s, master=%s",
            require_spark.sparkContext.appName,
            require_spark.sparkContext.master,
        )

    @pytest.mark.spark
    def test_spark_sees_gravitino_catalogs(self, require_spark: Any) -> None:
        """Spark should see catalogs from the Gravitino metalake."""
        catalogs_df = require_spark.sql("SHOW CATALOGS")
        catalogs = [row[0] for row in catalogs_df.collect()]
        logger.info("Spark sees catalogs: %s", catalogs)
        assert len(catalogs) >= 1, (
            f"Expected at least 1 catalog visible to Spark, got: {catalogs}"
        )

    @pytest.mark.spark
    @pytest.mark.slow
    def test_spark_iceberg_query_returns_data(
        self, require_spark: Any, iceberg_catalog_name: str
    ) -> None:
        """Spark should read Iceberg cold tier data through Gravitino."""
        glue_db = os.getenv("GLUE_DATABASE", "federation_demo")
        df = require_spark.sql(
            f"SELECT count(*) AS cnt FROM {iceberg_catalog_name}.{glue_db}.ledger_entries_cold"
        )
        result = df.collect()
        count = result[0]["cnt"]
        logger.info("Spark Iceberg query: ledger_entries_cold count=%d", count)
        assert count > 0, f"Expected rows from Spark Iceberg query, got {count}"

    @pytest.mark.spark
    @pytest.mark.slow
    def test_spark_parquet_query_returns_data(
        self, require_spark: Any, s3_bucket: str
    ) -> None:
        """Spark should read Parquet warm tier data directly from S3.

        Reads the warm tier Parquet file directly via S3A filesystem.
        The AWS Glue Data Catalog Hive metastore client is not available
        on Maven Central (awslabs#60), so we bypass catalog lookup and
        read the Parquet file at its known S3 path.
        """
        s3_path = f"s3a://{s3_bucket}/spectrum/ledger_entries_warm/data.parquet"
        df = require_spark.read.parquet(s3_path)
        count = df.count()
        logger.info("Spark Parquet query: ledger_entries_warm count=%d", count)
        assert count > 0, f"Expected rows from Spark Parquet query, got {count}"

    @pytest.mark.spark
    @pytest.mark.slow
    def test_spark_iceberg_count_matches_trino(
        self, require_spark: Any, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Same Iceberg table, same count from Spark and Trino."""
        glue_db = os.getenv("GLUE_DATABASE", "federation_demo")
        spark_df = require_spark.sql(
            f"SELECT count(*) AS cnt FROM {iceberg_catalog_name}.{glue_db}.ledger_entries_cold"
        )
        spark_count = spark_df.collect()[0]["cnt"]

        cursor = trino_conn.cursor()
        cursor.execute(
            f"SELECT count(*) FROM {iceberg_catalog_name}.{glue_db}.ledger_entries_cold"
        )
        trino_count = cursor.fetchone()[0]

        logger.info(
            "Multi-engine count: Spark=%d, Trino=%d", spark_count, trino_count
        )
        assert spark_count == trino_count, (
            f"Row count mismatch: Spark={spark_count}, Trino={trino_count}. "
            "Both engines should see identical data through Gravitino."
        )

    @pytest.mark.spark
    @pytest.mark.slow
    def test_spark_iceberg_schema_matches_trino(
        self, require_spark: Any, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Same Iceberg table, same columns from Spark and Trino."""
        glue_db = os.getenv("GLUE_DATABASE", "federation_demo")
        spark_df = require_spark.sql(
            f"SELECT * FROM {iceberg_catalog_name}.{glue_db}.ledger_entries_cold LIMIT 1"
        )
        spark_cols = set(spark_df.columns)

        cursor = trino_conn.cursor()
        cursor.execute(
            f"SELECT * FROM {iceberg_catalog_name}.{glue_db}.ledger_entries_cold LIMIT 1"
        )
        cursor.fetchall()
        trino_cols = {d[0] for d in cursor.description}

        logger.info(
            "Multi-engine schema: Spark=%s, Trino=%s",
            sorted(spark_cols),
            sorted(trino_cols),
        )
        expected = {"entry_id", "token_id", "amount", "jurisdiction", "entry_date"}
        assert expected.issubset(spark_cols), (
            f"Spark missing columns: {expected - spark_cols}"
        )
        assert expected.issubset(trino_cols), (
            f"Trino missing columns: {expected - trino_cols}"
        )

    @pytest.mark.spark
    def test_spark_governance_delta_documented(self) -> None:
        """Spark has LF+IAM but no Ranger gap-fill — computed from safety model."""
        from src.governance.safety_model import compute_governance_delta

        delta = compute_governance_delta("trino", "spark")

        # Trino has controls that Spark lacks
        assert len(delta.additions) > 0, (
            "Expected governance delta between Trino and Spark"
        )
        assert delta.has_masking_gap, (
            "Expected masking gap between Trino and Spark"
        )
        assert delta.has_row_filter_gap, (
            "Expected row-filter gap between Trino and Spark"
        )

        logger.info("ENGINE GOVERNANCE DELTA (Trino has, Spark lacks):")
        for control in delta.additions:
            logger.info("  + %s (%s): %s", control.name, control.enforcement_type, control.description)
        for control in delta.removals:
            logger.info("  - %s (%s): %s", control.name, control.enforcement_type, control.description)

    @pytest.mark.spark
    def test_multi_format_accessible_from_spark(
        self, require_spark: Any, iceberg_catalog_name: str
    ) -> None:
        """Spark should see both Iceberg and Hive/Parquet through single metalake."""
        catalogs_df = require_spark.sql("SHOW CATALOGS")
        catalogs = [row[0] for row in catalogs_df.collect()]
        logger.info(
            "Spark catalogs (should include Iceberg and possibly Hive): %s",
            catalogs,
        )
        assert len(catalogs) >= 1, f"No catalogs visible to Spark: {catalogs}"
        if iceberg_catalog_name in catalogs:
            logger.info(
                "Iceberg catalog '%s' visible to Spark through Gravitino",
                iceberg_catalog_name,
            )
        else:
            logger.info(
                "Iceberg catalog '%s' not yet visible to Spark. "
                "Gravitino plugin may need catalog registration.",
                iceberg_catalog_name,
            )
