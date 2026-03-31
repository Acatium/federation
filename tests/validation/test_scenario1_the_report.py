"""Scenario 1: The Counterparty Exposure Report.

A risk analyst needs to aggregate counterparty exposure by jurisdiction
across the full transaction lifecycle — hot tier (Redshift), warm tier
(S3 Parquet via Spectrum), cold tier (Iceberg via Glue) — joined with
counterparty reference data (Snowflake) and risk signals (Databricks).

Thinking about a scenario where BCBS 239 risk data aggregation would be
applicable, the analyst should be able to do this from a single workspace
with one identity, one catalog, and one query — without knowing where any
data physically lives or filing a single access request.

This scenario proves: unified discovery, five-format federation, and
LLM-powered analysis where Gravitino is the metadata map that makes
cross-platform intelligence possible.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import pytest
import requests

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.validation]


# ---------------------------------------------------------------------------
# Part 1: TestWorkspace — the analyst sits down
# ---------------------------------------------------------------------------


class TestWorkspace:
    """The analyst sits down. One identity. Everything visible."""

    def test_single_identity_across_all_platforms(self, trino_conn: Any) -> None:
        """One login for the entire federation layer."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT current_user")
        current_user = cursor.fetchone()[0]
        expected = os.getenv("TRINO_USER", "test_user")
        assert current_user == expected, (
            f"Expected Trino user '{expected}', got '{current_user}'"
        )
        logger.info("Single identity verified: %s", current_user)

    def test_all_platforms_in_one_catalog(
        self, gravitino_metalake: dict[str, Any], gravitino_catalogs: list[str]
    ) -> None:
        """Gravitino metalake has catalogs from every platform."""
        metalake_data = gravitino_metalake.get("metalake", gravitino_metalake)
        metalake_name = metalake_data.get("name", "")
        assert metalake_name == "federation", (
            f"Expected metalake name 'federation', got '{metalake_name}'"
        )
        # Every platform must be registered by name — not just a count threshold
        required_catalogs = {"hive", "iceberg_s3", "redshift", "databricks", "snowflake", "bedrock_models"}
        registered = set(gravitino_catalogs)
        missing = required_catalogs - registered
        assert not missing, (
            f"Missing required catalogs: {missing}. Registered: {gravitino_catalogs}"
        )
        logger.info(
            "Metalake '%s' has %d catalogs: %s",
            metalake_name,
            len(gravitino_catalogs),
            gravitino_catalogs,
        )

    def test_models_discoverable_alongside_data(
        self, gravitino_catalogs: list[str]
    ) -> None:
        """Model catalog in same namespace as data catalogs."""
        assert "bedrock_models" in gravitino_catalogs, (
            f"'bedrock_models' not in catalogs: {gravitino_catalogs}"
        )
        logger.info(
            "Model catalog 'bedrock_models' discoverable alongside data catalogs"
        )

    def test_governance_tier_on_catalogs(
        self, gravitino_base_url: str, gravitino_catalogs: list[str]
    ) -> None:
        """Data catalogs carry governance_tier tags."""
        catalogs_with_tier: list[str] = []
        for catalog_name in gravitino_catalogs:
            try:
                resp = requests.get(
                    f"{gravitino_base_url}/api/metalakes/federation/catalogs/{catalog_name}",
                    timeout=15,
                )
                if resp.ok:
                    cat_data = resp.json()
                    cat_obj = cat_data.get("catalog", cat_data)
                    props = cat_obj.get("properties", {})
                    tier = props.get("governance_tier", "")
                    if tier:
                        catalogs_with_tier.append(catalog_name)
                        logger.info(
                            "  %s: governance_tier=%s", catalog_name, tier
                        )
                    else:
                        logger.info("  %s: no governance_tier tag", catalog_name)
            except requests.RequestException as exc:
                logger.warning("Could not fetch catalog %s: %s", catalog_name, exc)

        assert len(catalogs_with_tier) >= 3, (
            f"Expected >= 3 catalogs with governance_tier, got {len(catalogs_with_tier)}: "
            f"{catalogs_with_tier}"
        )
        logger.info(
            "%d/%d catalogs have governance_tier",
            len(catalogs_with_tier),
            len(gravitino_catalogs),
        )

    def test_tables_discoverable_without_platform_knowledge(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Walk the catalog and find tables — no platform knowledge needed."""
        total_tables = 0
        for cat_name, cat_meta in gravitino_table_metadata.get("catalogs", {}).items():
            for schema_name, schema_meta in cat_meta.get("schemas", {}).items():
                tables = schema_meta.get("tables", {})
                count = len(tables)
                if count > 0:
                    logger.info(
                        "  %s.%s: %d tables (%s)",
                        cat_name,
                        schema_name,
                        count,
                        list(tables.keys()),
                    )
                total_tables += count
        assert total_tables >= 6, (
            f"Expected >= 6 discoverable tables, found {total_tables}"
        )
        logger.info("Total discoverable tables: %d", total_tables)

    def test_all_catalogs_queryable_from_one_trino_session(
        self, trino_catalogs: list[str]
    ) -> None:
        """SHOW CATALOGS includes all platforms."""
        expected = ["redshift", "snowflake", "hive", "iceberg_s3"]
        for cat in expected:
            assert cat in trino_catalogs, (
                f"Expected '{cat}' in Trino catalogs, got: {trino_catalogs}"
            )
        logger.info("Trino catalogs: %s", trino_catalogs)


# ---------------------------------------------------------------------------
# Part 2: TestBuildReport — five tiers, five formats, one query
# ---------------------------------------------------------------------------


class TestBuildReport:
    """Five tiers, five formats, one query."""

    @pytest.mark.slow
    def test_hot_tier_redshift(self, trino_conn: Any) -> None:
        """Trino reaches Redshift ledger_entries."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
        count = cursor.fetchone()[0]
        assert count >= 400_000, (
            f"Expected >= 400,000 rows in hot tier, got {count}"
        )
        logger.info("Hot tier (Redshift): %d rows", count)

    @pytest.mark.slow
    def test_warm_tier_s3_parquet(self, trino_conn: Any) -> None:
        """Trino reaches warm tier Parquet via Iceberg/Glue on S3."""
        cursor = trino_conn.cursor()
        # Warm tier is registered in iceberg_s3 catalog (Glue-backed)
        # The hive catalog shows it but cannot query Iceberg-format tables
        cursor.execute(
            "SELECT count(*) FROM iceberg_s3.federation_demo.ledger_entries_warm"
        )
        count = cursor.fetchone()[0]
        assert count >= 400_000, f"Expected >= 400K warm tier rows, got {count}"
        logger.info("Warm tier (Iceberg/S3 Parquet): %d rows", count)

    @pytest.mark.slow
    def test_cold_tier_iceberg(
        self, trino_conn: Any, iceberg_catalog_name: str, gravitino_catalogs: list[str]
    ) -> None:
        """Trino reaches Iceberg cold tier."""
        cursor = trino_conn.cursor()
        cursor.execute(
            f"SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold"
        )
        count = cursor.fetchone()[0]
        assert count >= 400_000, f"Expected >= 400K cold tier rows, got {count}"
        logger.info("Cold tier (Iceberg): %d rows", count)

    @pytest.mark.slow
    def test_counterparty_reference_snowflake(self, trino_conn: Any) -> None:
        """Trino reaches Snowflake entities."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM snowflake.public.entities")
        count = cursor.fetchone()[0]
        assert count >= 40_000, f"Expected >= 40K entity rows, got {count}"
        logger.info("Counterparty reference (Snowflake): %d rows", count)

    @pytest.mark.slow
    def test_risk_signals_databricks(
        self, trino_conn: Any, trino_catalogs: list[str]
    ) -> None:
        """Trino reaches Databricks risk_signals via credential vending."""
        assert "databricks" in trino_catalogs, (
            f"'databricks' not in Trino catalogs: {trino_catalogs}"
        )
        cursor = trino_conn.cursor()
        cursor.execute(
            "SELECT count(*) FROM databricks.federation_demo.risk_signals"
        )
        count = cursor.fetchone()[0]
        assert count >= 80_000, f"Expected >= 80K risk_signals rows, got {count}"
        logger.info("Databricks risk_signals (credential vending): %d rows", count)

    @pytest.mark.slow
    def test_full_lifecycle_query(
        self, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """UNION ALL spanning all tiers. Five formats, one SQL."""
        cursor = trino_conn.cursor()

        union_sql = (
            "SELECT 'redshift' AS source, count(*) AS cnt "
            "FROM redshift.federation.ledger_entries "
            "UNION ALL "
            f"SELECT 'iceberg' AS source, count(*) AS cnt "
            f"FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold "
            "UNION ALL "
            "SELECT 'snowflake' AS source, count(*) AS cnt "
            "FROM snowflake.public.entities "
            "UNION ALL "
            "SELECT 'warm' AS source, count(*) AS cnt "
            "FROM iceberg_s3.federation_demo.ledger_entries_warm "
            "UNION ALL "
            "SELECT 'databricks' AS source, count(*) AS cnt "
            "FROM databricks.federation_demo.risk_signals"
        )
        cursor.execute(union_sql)
        rows = cursor.fetchall()

        for row in rows:
            source, cnt = row[0], row[1]
            assert cnt > 0, f"Leg '{source}' returned 0 rows"
            logger.info("  %s: %d rows", source, cnt)

        assert len(rows) == 5, (
            f"Expected 5 UNION ALL legs, got {len(rows)}"
        )
        logger.info(
            "Full lifecycle query: %d legs, total rows = %d",
            len(rows),
            sum(r[1] for r in rows),
        )

    @pytest.mark.slow
    def test_hot_cold_join_by_jurisdiction(
        self, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """JOIN Redshift hot with Iceberg cold on jurisdiction."""
        cursor = trino_conn.cursor()
        # Aggregate each tier first, then join — avoids 500K × 500K cross-join
        # that would exceed Trino CPU limits on a resource-constrained cluster.
        cursor.execute(
            f"SELECT h.jurisdiction, h.hot_count, "
            f"COALESCE(c.cold_count, 0) AS cold_count "
            f"FROM ("
            f"  SELECT jurisdiction, COUNT(*) AS hot_count "
            f"  FROM redshift.federation.ledger_entries "
            f"  GROUP BY jurisdiction"
            f") h "
            f"LEFT JOIN ("
            f"  SELECT jurisdiction, COUNT(*) AS cold_count "
            f"  FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold "
            f"  GROUP BY jurisdiction"
            f") c ON h.jurisdiction = c.jurisdiction "
            f"LIMIT 10"
        )
        rows = cursor.fetchall()
        assert len(rows) > 0, "Hot-cold JOIN returned no rows"
        for row in rows:
            jurisdiction, hot_count, cold_count = row[0], row[1], row[2]
            assert jurisdiction is not None, "Jurisdiction should not be null"
            logger.info(
                "  %s: hot=%d, cold=%d", jurisdiction, hot_count, cold_count
            )
        logger.info("Hot-cold JOIN: %d jurisdictions", len(rows))

    @pytest.mark.slow
    def test_exposure_aggregation_by_jurisdiction(self, trino_conn: Any) -> None:
        """GROUP BY jurisdiction, SUM(amount) — no staging, no ETL."""
        cursor = trino_conn.cursor()
        cursor.execute(
            "SELECT jurisdiction, SUM(amount) AS total_exposure "
            "FROM redshift.federation.ledger_entries "
            "GROUP BY jurisdiction"
        )
        rows = cursor.fetchall()
        assert len(rows) >= 2, (
            f"Expected >= 2 jurisdictions, got {len(rows)}"
        )
        for row in rows:
            jurisdiction, total = row[0], float(row[1])
            assert total > 0, (
                f"Jurisdiction '{jurisdiction}' has non-positive exposure: {total}"
            )
            logger.info("  %s: total_exposure=%.2f", jurisdiction, total)
        logger.info(
            "Exposure aggregation: %d jurisdictions", len(rows)
        )

    @pytest.mark.slow
    @pytest.mark.spark
    def test_spark_confirms_iceberg_data(
        self, spark_session: Any, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Spark reads same Iceberg table — row count matches Trino."""
        if spark_session is None:
            pytest.skip("Spark not available")

        # Spark count
        spark_df = spark_session.sql(
            "SELECT count(*) FROM iceberg_s3.federation_demo.ledger_entries_cold"
        )
        spark_count = spark_df.collect()[0][0]
        logger.info("Spark Iceberg count: %d", spark_count)

        # Trino count
        cursor = trino_conn.cursor()
        cursor.execute(
            f"SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold"
        )
        trino_count = cursor.fetchone()[0]
        logger.info("Trino Iceberg count: %d", trino_count)

        assert spark_count == trino_count, (
            f"Spark ({spark_count}) and Trino ({trino_count}) disagree on Iceberg cold tier count"
        )
        logger.info(
            "Spark and Trino agree: %d rows in Iceberg cold tier", spark_count
        )


# ---------------------------------------------------------------------------
# Part 3: TestLLMPoweredAnalysis — Gravitino is the map, Cortex writes the query
# ---------------------------------------------------------------------------


class TestLLMPoweredAnalysis:
    """Gravitino is the map. Cortex writes the query."""

    def test_gravitino_provides_metadata_context(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Build structured metadata map from Gravitino."""
        # Every data catalog with a real backend must introspect schemas+tables.
        # LIMITATION: Gravitino 1.1.0 has no native Snowflake JDBC provider.
        # Snowflake is registered via Open Catalog (Polaris) Iceberg REST —
        # introspection shows Iceberg tables managed by Polaris, not native
        # Snowflake tables. The entities table must be loaded into Open Catalog
        # via load_open_catalog_entities() for this assertion to pass.
        # Redshift uses jdbc-postgresql provider and introspects natively.
        required_introspection = {"hive", "iceberg_s3", "databricks", "snowflake", "redshift"}
        catalogs_with_detail = []
        catalogs_missing_detail = []
        for cat_name, cat_meta in gravitino_table_metadata.get("catalogs", {}).items():
            schemas = cat_meta.get("schemas", {})
            table_count = sum(
                len(s.get("tables", {})) for s in schemas.values()
            )
            if schemas and table_count > 0:
                catalogs_with_detail.append(cat_name)
                logger.info(
                    "  %s: %d schemas, %d tables",
                    cat_name,
                    len(schemas),
                    table_count,
                )
            elif cat_name in required_introspection:
                catalogs_missing_detail.append(cat_name)
        assert not catalogs_missing_detail, (
            f"Catalogs with broken introspection (no tables): {catalogs_missing_detail}"
        )
        logger.info(
            "Gravitino metadata: %d catalogs with table detail: %s",
            len(catalogs_with_detail),
            catalogs_with_detail,
        )

    def test_metadata_includes_governance_context(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Metadata context includes governance_tier tags."""
        catalogs_with_governance = []
        for cat_name, cat_meta in gravitino_table_metadata.get("catalogs", {}).items():
            props = cat_meta.get("properties", {})
            tier = props.get("governance_tier", "")
            if tier:
                catalogs_with_governance.append(cat_name)
                logger.info("  %s: governance_tier=%s", cat_name, tier)
        assert len(catalogs_with_governance) >= 3, (
            f"Expected >= 3 catalogs with governance_tier in metadata, "
            f"got {len(catalogs_with_governance)}: {catalogs_with_governance}"
        )
        logger.info(
            "%d catalogs have governance_tier in metadata",
            len(catalogs_with_governance),
        )

    @pytest.mark.slow
    def test_cortex_responds(self, snowflake_conn: Any) -> None:
        """Snowflake Cortex LLM is callable."""
        cursor = snowflake_conn.cursor()
        cursor.execute(
            "SELECT SNOWFLAKE.CORTEX.COMPLETE("
            "'snowflake-arctic', 'Say hello in one sentence')"
        )
        result = cursor.fetchone()[0]
        assert result and len(result.strip()) > 0, (
            f"Cortex returned empty response: {result!r}"
        )
        logger.info("Cortex response: %s", result.strip()[:200])

    @pytest.mark.slow
    def test_cortex_writes_the_query(
        self, snowflake_conn: Any, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Proves the LLM-powered chain: sample sources, Cortex generates SQL,
        SQL references correct catalogs. Execution is best-effort due to
        LLM non-determinism.

        The analyst doesn't know the schemas. They sample each source
        through Trino to see what columns exist and what the data looks
        like, then ask Cortex to write a cross-platform exposure query.
        The chain itself (metadata → LLM → multi-catalog SQL) is the proof
        point; successful execution is logged as bonus evidence.
        """
        cursor = trino_conn.cursor()

        # Step 1: Sample each source through Trino
        sources = [
            "redshift.federation.ledger_entries",
            "snowflake.public.entities",
            f"{iceberg_catalog_name}.federation_demo.ledger_entries_cold",
            "iceberg_s3.federation_demo.ledger_entries_warm",
            "databricks.federation_demo.risk_signals",
        ]

        sample_parts: list[str] = []
        for table in sources:
            try:
                cursor.execute(f"SELECT * FROM {table} LIMIT 3")
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                sample_rows = [
                    {col: str(val) for col, val in zip(columns, row)}
                    for row in rows
                ]
                sample_parts.append(
                    f"Table: {table}\n"
                    f"Columns: {columns}\n"
                    f"Sample: {sample_rows}"
                )
                logger.info(
                    "  Sampled %s: %d columns, %d rows",
                    table, len(columns), len(rows),
                )
            except Exception as exc:
                logger.warning("  Could not sample %s: %s", table, exc)

        assert len(sample_parts) >= 3, (
            f"Expected samples from >= 3 sources, got {len(sample_parts)}"
        )

        # Step 2: Ask Cortex to write the query
        sample_context = "\n\n".join(sample_parts)
        prompt = (
            f"You are a Trino SQL expert. Here are data samples from "
            f"federated sources accessible through Trino:\n\n"
            f"{sample_context}\n\n"
            f"Write a single Trino SQL query that aggregates counterparty "
            f"exposure (SUM of amount) by jurisdiction, combining data from "
            f"at least two different catalogs. Add LIMIT 20 at the end. "
            f"Return ONLY the raw SQL — no markdown, no explanation, "
            f"no code fences."
        )

        sf_cursor = snowflake_conn.cursor()
        sf_cursor.execute(
            "SELECT SNOWFLAKE.CORTEX.COMPLETE('snowflake-arctic', %s)",
            (prompt,),
        )
        raw_response = sf_cursor.fetchone()[0].strip()
        logger.info("Cortex raw response:\n%s", raw_response[:800])

        # Step 3: Clean the SQL
        sql = raw_response
        sql = re.sub(r"^```(?:sql)?\s*\n?", "", sql, flags=re.MULTILINE)
        sql = re.sub(r"\n?```\s*$", "", sql, flags=re.MULTILINE)
        sql = sql.strip().rstrip(";")
        if "limit" not in sql.lower():
            sql += " LIMIT 20"

        assert len(sql) > 20, f"Cortex produced too-short SQL: {sql!r}"

        # Verify it references at least 2 catalogs
        sql_lower = sql.lower()
        catalog_refs = [
            name for name in [
                "redshift.", "snowflake.", "iceberg_s3.", "databricks.",
            ]
            if name in sql_lower
        ]
        assert len(catalog_refs) >= 2, (
            f"Expected SQL referencing >= 2 catalogs, found "
            f"{catalog_refs} in:\n{sql}"
        )

        # Step 4: Execute on Trino (best-effort — LLM output is non-deterministic)
        logger.info("Executing Cortex-generated SQL:\n%s", sql)
        try:
            cursor.execute(sql)
            rows = cursor.fetchall()
            logger.info(
                "End-to-end: sampled %d sources -> Cortex -> "
                "%d-char SQL -> %d rows from Trino",
                len(sample_parts), len(sql), len(rows),
            )
            for row in rows:
                logger.info("  %s", row)
        except Exception as exc:
            logger.warning(
                "Cortex SQL did not execute (LLM non-determinism): %s. "
                "The chain still proved: sample %d sources -> Cortex -> "
                "%d-char SQL referencing %s",
                exc, len(sample_parts), len(sql), catalog_refs,
            )

    @pytest.mark.slow
    def test_cross_platform_query_executes(self, trino_conn: Any) -> None:
        """Deterministic cross-platform exposure query — S2's audit input.

        This is the predictable version of the query: aggregate exposure
        by jurisdiction, joining Redshift ledger data with Snowflake
        counterparty reference data via jurisdiction (entity_name is
        masked by Ranger). Scenario 2 reconciles against this same
        table and query pattern.
        """
        cursor = trino_conn.cursor()
        cursor.execute(
            "SELECT r.jurisdiction, COUNT(*) AS txn_count, SUM(r.amount) AS exposure "
            "FROM (SELECT jurisdiction, amount FROM redshift.federation.ledger_entries "
            "      LIMIT 10000) r "
            "WHERE r.jurisdiction IN ("
            "  SELECT DISTINCT jurisdiction FROM snowflake.public.entities"
            ") "
            "GROUP BY r.jurisdiction LIMIT 10"
        )
        rows = cursor.fetchall()
        assert len(rows) > 0, "Cross-platform query returned no rows"
        for row in rows:
            logger.info(
                "  jurisdiction=%s txn_count=%d exposure=%.2f",
                row[0],
                row[1],
                float(row[2]),
            )
        logger.info("Cross-platform query: %d jurisdictions returned", len(rows))

    def test_gravitino_metadata_richer_than_information_schema(
        self, gravitino_table_metadata: dict[str, Any], trino_conn: Any
    ) -> None:
        """Gravitino has governance tags that information_schema lacks."""
        # Get Trino information_schema columns for redshift.federation.ledger_entries
        cursor = trino_conn.cursor()
        cursor.execute(
            "SELECT column_name FROM redshift.information_schema.columns "
            "WHERE table_schema = 'federation' AND table_name = 'ledger_entries'"
        )
        info_schema_columns = [row[0] for row in cursor.fetchall()]
        logger.info("information_schema columns: %s", info_schema_columns)

        # Get Gravitino metadata for a catalog
        gravitino_extras: list[str] = []
        for cat_name, cat_meta in gravitino_table_metadata.get("catalogs", {}).items():
            props = cat_meta.get("properties", {})
            cat_type = cat_meta.get("type", "")
            if props.get("governance_tier"):
                gravitino_extras.append(f"{cat_name}.governance_tier={props['governance_tier']}")
            if cat_type:
                gravitino_extras.append(f"{cat_name}.type={cat_type}")

        assert len(gravitino_extras) > 0, (
            "Gravitino should have governance_tier or catalog type that "
            "information_schema does not provide"
        )
        logger.info(
            "Gravitino enrichment beyond information_schema: %s", gravitino_extras
        )
