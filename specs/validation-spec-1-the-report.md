# Validation Spec 1: "The Counterparty Exposure Report"

## Session Prompt

Paste this into a fresh Claude Code terminal:

```
Read specs/validation-spec-1-the-report.md and implement it exactly. This is the first of three validation test files. Before writing any tests:

1. Create tests/validation/__init__.py (empty)
2. Create tests/validation/conftest.py with the fixtures specified in the spec
3. Add "validation: Validation proof-point tests" to the markers list in pyproject.toml
4. Validate infrastructure: SSH to EC2 (ssh -i ~/.ssh/federation-demo-key.pem ec2-user@<EC2_HOST>) and verify:
   a. Cortex on Snowflake: connect via snowflake_conn and run SELECT SNOWFLAKE.CORTEX.COMPLETE('snowflake-arctic', 'Hello') — if Cortex isn't available, check how to enable it
   b. Databricks via Trino: run SELECT count(*) FROM databricks.<schema>.risk_factors via Trino
   c. Masking for test_user: compare SELECT token_id FROM redshift.federation.ledger_entries LIMIT 5 via Trino vs direct Redshift
5. Then implement test_scenario1_the_report.py with all 22 tests
6. Run pytest tests/validation/test_scenario1_the_report.py -v --tb=short and fix all failures
7. All tests must be correct — fix errors, do not alter tests unless the test is proven to be inaccurate or ineffective
```

---

## Context

This is a federated data governance reference implementation. Five platforms (AWS Redshift, S3/Spectrum, Iceberg/Glue, Snowflake, Databricks) are unified through Apache Gravitino (catalog), Apache Ranger (policy), and Trino (query). The test suite tells a story an executive can follow.

This scenario: a risk analyst needs to aggregate counterparty exposure by jurisdiction across the full transaction lifecycle. They sit down with one identity, discover data from five platforms, build the report with one query, and use an LLM (Snowflake Cortex) to analyze the results — with Gravitino providing the metadata map that makes LLM-powered federation possible.

## Data Model

| Table | Platform | Format | Rows | Tier |
|-------|----------|--------|------|------|
| `ledger_entries` | Redshift | Native | 500K | Hot (2020+) |
| `ledger_entries_warm` | S3 via Spectrum | Parquet | 500K | Warm |
| `ledger_entries_cold` | S3 via Glue | Iceberg | 500K | Cold (2018-2019) |
| `entities` | Snowflake | Native | 50K | Reference |
| `risk_factors` | Databricks | Delta | 1K | Risk signals |

Columns in ledger_entries: entry_id, token_id, account_ref, entity_name, amount, jurisdiction, entry_date

## Existing Infrastructure to Reuse

### Root conftest fixtures (tests/conftest.py — DO NOT MODIFY)

All session-scoped, auto-skip if env var missing:

- `trino_conn` — `trino.dbapi.connect(host=TRINO_HOST, port=TRINO_PORT, user=TRINO_USER)`. User from `TRINO_USER` env (default "test_user").
- `redshift_conn` — `psycopg2.connect(host=REDSHIFT_HOST, ...)`. SSLmode=require.
- `snowflake_conn` — `snowflake.connector.connect(account=SNOWFLAKE_ACCOUNT, ...)`.
- `ranger_policies` — GET `/service/public/v2/api/policy?serviceName=dev_trino` from Ranger REST API. Returns `list[dict]`.
- `ranger_base_url` — `http://{RANGER_HOST}:{RANGER_PORT}` (defaults: localhost:6080).
- `ranger_auth` — tuple `(admin_user, admin_password)`.
- `gravitino_base_url` — `http://{GRAVITINO_HOST}:{GRAVITINO_PORT}` (defaults: localhost:8090).
- `gravitino_metalake` — GET `/api/metalakes/federation`. Returns dict.
- `gravitino_catalogs` — GET `/api/metalakes/federation/catalogs`. Returns `list[str]` of catalog names.
- `spark_session` — PySpark with native Iceberg GlueCatalog. Returns None if unavailable. Tests MUST handle None.
- `iceberg_catalog_name` — env `ICEBERG_CATALOG` (default "iceberg_s3").
- `s3_bucket` — env `S3_BUCKET`.
- `gravitino_model_catalog` — `BedrockModelCatalog().get_catalog_info()`.
- `bedrock_models` — `from src.models.bedrock_catalog import BEDROCK_MODELS`.

### Src modules

- `src/models/bedrock_catalog.py` — `BedrockModelCatalog`, `BEDROCK_MODELS` list
- `src/governance/safety_model.py` — safety model functions

## What to Create

### `tests/validation/__init__.py`

Empty file.

### `tests/validation/conftest.py`

```python
"""Validation suite fixtures and marker registration."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import polars as pl
import pytest
import requests

logger = logging.getLogger(__name__)


def pytest_configure(config: Any) -> None:
    """Register the validation marker."""
    config.addinivalue_line(
        "markers",
        "validation: Validation proof-point tests",
    )


@pytest.fixture(scope="session")
def solr_audit_url() -> str:
    """Solr audit query URL."""
    solr_host = os.getenv("SOLR_HOST", os.getenv("RANGER_HOST", "localhost"))
    return f"http://{solr_host}:8983/solr/ranger_audits/select"


@pytest.fixture(scope="session")
def trino_catalogs(trino_conn: Any) -> list[str]:
    """Cached list of Trino catalogs."""
    cursor = trino_conn.cursor()
    cursor.execute("SHOW CATALOGS")
    return [row[0] for row in cursor.fetchall()]


@pytest.fixture(scope="session")
def entitlement_matrix_df(ranger_policies: list[dict[str, Any]]) -> pl.DataFrame:
    """Entitlement matrix as Polars DataFrame."""
    from src.reports.entitlement_matrix import EntitlementMatrix, MATRIX_COLUMNS

    try:
        return EntitlementMatrix().build(policies=ranger_policies)
    except Exception as exc:
        logger.warning("Could not build entitlement matrix: %s", exc)
        return pl.DataFrame({col: pl.Series([], dtype=pl.Utf8) for col in MATRIX_COLUMNS})


@pytest.fixture(scope="session")
def gravitino_table_metadata(
    gravitino_base_url: str, gravitino_catalogs: list[str]
) -> dict[str, Any]:
    """Walk Gravitino API to build structured metadata context.

    Returns dict with catalog → schemas → tables → columns structure,
    suitable for feeding to an LLM as context.
    """
    metadata: dict[str, Any] = {"catalogs": {}}
    for catalog_name in gravitino_catalogs:
        cat_meta: dict[str, Any] = {"schemas": {}}
        try:
            # Get catalog details
            resp = requests.get(
                f"{gravitino_base_url}/api/metalakes/federation/catalogs/{catalog_name}",
                timeout=15,
            )
            if resp.ok:
                cat_data = resp.json()
                cat_obj = cat_data.get("catalog", cat_data)
                cat_meta["properties"] = cat_obj.get("properties", {})
                cat_meta["type"] = cat_obj.get("type", "RELATIONAL")

            # Get schemas
            resp = requests.get(
                f"{gravitino_base_url}/api/metalakes/federation/catalogs/{catalog_name}/schemas",
                timeout=15,
            )
            if resp.ok:
                schemas_data = resp.json()
                schema_ids = schemas_data.get("identifiers", [])
                for schema_id in schema_ids:
                    schema_name = schema_id.get("name", "")
                    if schema_name.startswith("__"):
                        continue  # Skip internal schemas
                    tables_meta: dict[str, Any] = {}
                    # Get tables
                    try:
                        resp_t = requests.get(
                            f"{gravitino_base_url}/api/metalakes/federation/catalogs/"
                            f"{catalog_name}/schemas/{schema_name}/tables",
                            timeout=15,
                        )
                        if resp_t.ok:
                            tables_data = resp_t.json()
                            for tbl_id in tables_data.get("identifiers", []):
                                tables_meta[tbl_id.get("name", "")] = {}
                    except requests.RequestException:
                        pass
                    cat_meta["schemas"][schema_name] = {"tables": tables_meta}
        except requests.RequestException as exc:
            logger.warning("Could not fetch metadata for catalog %s: %s", catalog_name, exc)
        metadata["catalogs"][catalog_name] = cat_meta
    return metadata


@pytest.fixture(autouse=True)
def _reset_redshift_transaction(request: pytest.FixtureRequest) -> None:
    """Reset Redshift connection if it's in a failed transaction state."""
    redshift_conn = (
        request.getfixturevalue("redshift_conn")
        if "redshift_conn" in request.fixturenames
        else None
    )
    if redshift_conn is not None:
        try:
            redshift_conn.rollback()
        except Exception:
            pass
```

### `tests/validation/test_scenario1_the_report.py`

**Module docstring:**
```
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
```

**Module-level marker:** `pytestmark = [pytest.mark.validation]`

---

#### Part 1: TestWorkspace (6 tests)

```python
class TestWorkspace:
    """The analyst sits down. One identity. Everything visible."""

    def test_single_identity_across_all_platforms(self, trino_conn: Any) -> None:
        """One login for the entire federation layer."""
        # SELECT current_user via Trino
        # Assert matches TRINO_USER env var (default "test_user")

    def test_all_platforms_in_one_catalog(
        self, gravitino_metalake: dict[str, Any], gravitino_catalogs: list[str]
    ) -> None:
        """Gravitino metalake has catalogs from every platform."""
        # Assert metalake name == "federation"
        # Assert len(gravitino_catalogs) >= 5
        # Log which catalogs are present

    def test_models_discoverable_alongside_data(
        self, gravitino_catalogs: list[str]
    ) -> None:
        """Model catalog in same namespace as data catalogs."""
        # Assert "bedrock_models" in gravitino_catalogs

    def test_governance_tier_on_every_catalog(
        self, gravitino_base_url: str, gravitino_catalogs: list[str]
    ) -> None:
        """Every catalog carries a governance_tier tag."""
        # For each catalog: GET /api/metalakes/federation/catalogs/{name}
        # Check properties for governance_tier
        # Assert at least 3 catalogs have governance_tier set

    def test_tables_discoverable_without_platform_knowledge(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Walk the catalog and find tables — no platform knowledge needed."""
        # Count total tables across all catalogs/schemas
        # Assert >= 6 tables

    def test_all_catalogs_queryable_from_one_trino_session(
        self, trino_catalogs: list[str]
    ) -> None:
        """SHOW CATALOGS includes all platforms."""
        # Assert redshift, snowflake, hive, iceberg_s3 in trino_catalogs
        # Log full catalog list
```

#### Part 2: TestBuildReport (9 tests)

```python
class TestBuildReport:
    """Five tiers, five formats, one query."""

    @pytest.mark.slow
    def test_hot_tier_redshift(self, trino_conn: Any) -> None:
        """Trino reaches Redshift ledger_entries."""
        # SELECT count(*) FROM redshift.federation.ledger_entries
        # Assert count >= 400_000

    @pytest.mark.slow
    def test_warm_tier_spectrum_parquet(self, trino_conn: Any) -> None:
        """Trino reaches warm tier Parquet via Spectrum or Hive."""
        # Try: SELECT count(*) FROM hive.federation_demo.ledger_entries_warm
        # If that fails, try Spectrum path
        # Assert count > 0

    @pytest.mark.slow
    def test_cold_tier_iceberg(
        self, trino_conn: Any, iceberg_catalog_name: str, gravitino_catalogs: list[str]
    ) -> None:
        """Trino reaches Iceberg cold tier."""
        # SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold
        # Assert count > 0

    @pytest.mark.slow
    def test_counterparty_reference_snowflake(self, trino_conn: Any) -> None:
        """Trino reaches Snowflake entities."""
        # SELECT count(*) FROM snowflake.public.entities
        # Assert count > 0

    @pytest.mark.slow
    def test_risk_signals_databricks(
        self, trino_conn: Any, trino_catalogs: list[str]
    ) -> None:
        """Trino reaches Databricks risk_factors via credential vending."""
        # Assert "databricks" in trino_catalogs
        # Try: SHOW SCHEMAS FROM databricks
        # Try: SELECT count(*) FROM databricks.<schema>.risk_factors
        # Assert count > 0 or at minimum catalog is visible with schemas

    @pytest.mark.slow
    def test_full_lifecycle_query(
        self, trino_conn: Any, iceberg_catalog_name: str, trino_catalogs: list[str]
    ) -> None:
        """UNION ALL spanning all tiers. Five formats, one SQL."""
        # Build UNION ALL:
        #   SELECT 'redshift' AS source, count(*) AS cnt FROM redshift.federation.ledger_entries
        #   UNION ALL
        #   SELECT 'iceberg' AS source, count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold
        #   UNION ALL
        #   SELECT 'snowflake' AS source, count(*) FROM snowflake.public.entities
        #   UNION ALL (hive or spectrum warm tier if reachable)
        #   UNION ALL (databricks if reachable)
        # Assert all included legs return count > 0
        # Log the full result

    @pytest.mark.slow
    def test_hot_cold_join_by_jurisdiction(
        self, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """JOIN Redshift hot with Iceberg cold on jurisdiction."""
        # SELECT h.jurisdiction, COUNT(*) AS hot_count, COUNT(c.entry_id) AS cold_count
        # FROM redshift.federation.ledger_entries h
        # LEFT JOIN {iceberg_catalog_name}.federation_demo.ledger_entries_cold c
        #   ON h.jurisdiction = c.jurisdiction
        # GROUP BY h.jurisdiction
        # LIMIT 10
        # Assert rows returned, jurisdiction non-null

    @pytest.mark.slow
    def test_exposure_aggregation_by_jurisdiction(self, trino_conn: Any) -> None:
        """GROUP BY jurisdiction, SUM(amount) — no staging, no ETL."""
        # SELECT jurisdiction, SUM(amount) AS total_exposure
        # FROM redshift.federation.ledger_entries
        # GROUP BY jurisdiction
        # Assert >= 2 jurisdictions, all totals > 0

    @pytest.mark.slow
    @pytest.mark.spark
    def test_spark_confirms_iceberg_data(
        self, spark_session: Any, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Spark reads same Iceberg table — row count matches Trino."""
        # If spark_session is None: pytest.skip("Spark not available")
        # Spark: spark.sql("SELECT count(*) FROM iceberg_s3.federation_demo.ledger_entries_cold")
        # Trino: SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold
        # Assert spark_count == trino_count
```

#### Part 3: TestLLMPoweredAnalysis (7 tests)

```python
class TestLLMPoweredAnalysis:
    """Gravitino is the map. Cortex writes the query."""

    def test_gravitino_provides_metadata_context(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Build structured metadata map from Gravitino."""
        # Count platforms represented in metadata
        # Assert >= 3 catalogs with schema/table detail

    def test_metadata_includes_governance_context(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Metadata context includes governance_tier tags."""
        # Check properties on catalogs for governance_tier
        # Assert at least one catalog has governance_tier set

    @pytest.mark.slow
    def test_cortex_responds(self, snowflake_conn: Any) -> None:
        """Snowflake Cortex LLM is callable."""
        # cursor = snowflake_conn.cursor()
        # cursor.execute("SELECT SNOWFLAKE.CORTEX.COMPLETE('snowflake-arctic', 'Say hello in one sentence')")
        # result = cursor.fetchone()[0]
        # Assert result is non-empty string

    @pytest.mark.slow
    def test_cortex_generates_cross_platform_sql(
        self, snowflake_conn: Any, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Feed Gravitino metadata to Cortex. It generates cross-catalog SQL."""
        # Build a prompt:
        #   "Given these tables across catalogs: {metadata summary}
        #    Write a Trino SQL query to aggregate counterparty exposure by jurisdiction,
        #    joining data from at least two different catalogs."
        # Call SNOWFLAKE.CORTEX.COMPLETE() with the prompt
        # Parse the response for SQL
        # Assert the SQL references >= 2 catalog names (e.g., "redshift." and "snowflake.")

    @pytest.mark.slow
    def test_generated_sql_executes(self, trino_conn: Any) -> None:
        """A representative cross-platform query executes on Trino."""
        # Use a known-good cross-platform query as the representative:
        # SELECT r.jurisdiction, COUNT(*) AS txn_count, SUM(r.amount) AS exposure
        # FROM redshift.federation.ledger_entries r
        # JOIN snowflake.public.entities e ON r.entity_name = e.entity_name
        # GROUP BY r.jurisdiction LIMIT 10
        # (This proves the pattern works even if Cortex-generated SQL varies)
        # Assert rows returned

    @pytest.mark.slow
    def test_cortex_summarizes_exposure_results(self, snowflake_conn: Any) -> None:
        """Feed query results to Cortex for narrative summary."""
        # Hardcode representative exposure data or query it first
        # Prompt: "Summarize this counterparty exposure data: {data}"
        # Call SNOWFLAKE.CORTEX.COMPLETE()
        # Assert non-empty summary

    def test_gravitino_metadata_richer_than_information_schema(
        self, gravitino_table_metadata: dict[str, Any], trino_conn: Any
    ) -> None:
        """Gravitino has governance tags that information_schema lacks."""
        # Get Trino information_schema columns for one table
        # Get Gravitino metadata for same table
        # Assert Gravitino has governance_tier or catalog type that information_schema doesn't
```

## Code Standards

- Python 3.11+, type hints on all functions
- Docstrings on every test method — explain what it proves, not just what it does
- `logging` module only — no `print()`
- `pytestmark = [pytest.mark.validation]` at module level
- Slow tests (hitting live infra) also get `@pytest.mark.slow`
- Spark tests get `@pytest.mark.spark`
- Every assertion has a descriptive failure message
- Every test logs key values (counts, sources, metadata) for evidence capture
- No bare `except` — specific exception handling

## SQL Reference

| Query | Purpose |
|-------|---------|
| `SELECT count(*) FROM redshift.federation.ledger_entries` | Hot tier count (~500K) |
| `SELECT count(*) FROM snowflake.public.entities` | Counterparty reference |
| `SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold` | Cold tier count (~500K) |
| `SHOW CATALOGS` | List all Trino catalogs |
| `SHOW SCHEMAS FROM {catalog}` | List schemas in a catalog |
| `SELECT current_user` | Verify Trino identity |
| `SELECT SNOWFLAKE.CORTEX.COMPLETE(model, prompt)` | Call Cortex LLM |

## Environment Variables (from .env, loaded by conftest)

Key vars: `TRINO_HOST`, `TRINO_PORT`, `TRINO_USER`, `REDSHIFT_HOST`, `REDSHIFT_PORT`, `REDSHIFT_DATABASE`, `REDSHIFT_USER`, `REDSHIFT_PASSWORD`, `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PASSWORD`, `SNOWFLAKE_WAREHOUSE`, `SNOWFLAKE_DATABASE`, `RANGER_HOST`, `RANGER_PORT`, `GRAVITINO_HOST`, `GRAVITINO_PORT`, `S3_BUCKET`, `ICEBERG_CATALOG`, `SOLR_HOST`

## EC2 Access (for infra validation)

```bash
ssh -i ~/.ssh/federation-demo-key.pem ec2-user@<EC2_HOST>
# Containers: Gravitino (:8090), Ranger (:6080), Trino (:8080), Solr (:8983), MySQL (:3306), PostgreSQL (:5432)
# Config: /opt/federation/deploy/trino-config/
```
