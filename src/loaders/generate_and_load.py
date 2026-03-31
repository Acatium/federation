"""Generate deterministic demo data and load into Redshift, S3/Spectrum, Snowflake, Databricks.

Usage:
    source .venv/bin/activate
    python -m src.loaders.generate_and_load

All column names are sanitised (no production PCI/PII column names).
Uses Faker(seed=42) for deterministic generation and Polars for DataFrames.
"""

from __future__ import annotations

import io
import json
import logging
import os
import random
import tempfile
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import polars as pl
from dotenv import load_dotenv
from faker import Faker

from src.loaders.schemas import (
    COUNTERPARTY_CATEGORIES,
    COUNTERPARTY_REF_COLUMNS,
    COUNTERPARTY_STATUSES,
    ENTITIES_COLUMNS,
    ENTRY_CATEGORIES,
    ENTITY_TYPES,
    JURISDICTIONS,
    LEDGER_ENTRIES_COLUMNS,
    RISK_SIGNALS_COLUMNS,
    SIGNAL_TYPES,
    glue_columns,
    redshift_create_table_ddl,
    snowflake_create_table_ddl,
)
from src.utils.config import COLD_SEED_OFFSET, DATA_SEED, WARM_SEED_OFFSET
from src.utils.sql_safety import validate_identifier, validate_s3_bucket, validate_iam_role_arn

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("datagen")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
CONTRACTS_DIR = PROJECT_ROOT / "contracts"

HOT_ROWS = 500_000
WARM_ROWS = 500_000
COLD_ROWS = 500_000
ENTITY_ROWS = 50_000
RISK_ROWS = 100_000
COUNTERPARTY_ROWS = 10_000

# Batch size for Redshift COPY-via-INSERT and Snowflake bulk inserts
BATCH_SIZE = 10_000


# ===================================================================
# DATA GENERATORS — each returns a polars DataFrame
# ===================================================================

def generate_counterparty_ref(*, seed: int = DATA_SEED) -> pl.DataFrame:
    """Generate 10K counterparty reference rows."""
    fake = Faker()
    Faker.seed(seed)

    logger.info("Generating counterparty_ref (%d rows) ...", COUNTERPARTY_ROWS)
    random.seed(seed)

    counterparty_ids = list(range(1, COUNTERPARTY_ROWS + 1))
    counterparty_names = [fake.company() for _ in range(COUNTERPARTY_ROWS)]
    jurisdictions = [random.choice(JURISDICTIONS) for _ in range(COUNTERPARTY_ROWS)]
    categories = [random.choice(COUNTERPARTY_CATEGORIES) for _ in range(COUNTERPARTY_ROWS)]
    statuses = [random.choice(COUNTERPARTY_STATUSES) for _ in range(COUNTERPARTY_ROWS)]

    df = pl.DataFrame({
        "counterparty_id": counterparty_ids,
        "counterparty_name": counterparty_names,
        "jurisdiction": jurisdictions,
        "category": categories,
        "status": statuses,
    })
    logger.info("counterparty_ref generated: %d rows", len(df))
    return df


def generate_ledger_entries(
    counterparty_ids: list[int],
    *,
    n_rows: int,
    date_start: date,
    date_end: date,
    seed: int = DATA_SEED,
    id_offset: int = 0,
) -> pl.DataFrame:
    """Generate ledger entry rows with sanitised column names.

    Args:
        counterparty_ids: Valid counterparty IDs for FK.
        n_rows: How many rows to produce.
        date_start: Earliest entry_date.
        date_end: Latest entry_date.
        seed: RNG seed.
        id_offset: Starting entry_id (so hot/warm don't overlap).
    """
    fake = Faker()
    Faker.seed(seed)
    random.seed(seed)

    logger.info("Generating ledger_entries (%d rows, dates %s..%s) ...", n_rows, date_start, date_end)

    entry_ids: list[int] = []
    token_ids: list[str] = []
    account_refs: list[str] = []
    entity_names: list[str] = []
    amounts: list[float] = []
    jurisdictions: list[str] = []
    cp_ids: list[int] = []
    entry_dates: list[date] = []
    categories: list[str] = []

    for i in range(n_rows):
        entry_ids.append(id_offset + i + 1)
        # token_id: looks like a tokenised card — 16 hex chars
        token_ids.append(fake.hexify(text="^^^^^^^^^^^^^^^^", upper=False))
        account_refs.append(f"REF-{fake.bothify(text='???-########', letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ')}")
        entity_names.append(fake.name())
        amounts.append(round(random.uniform(1.00, 250_000.00), 2))
        jurisdictions.append(random.choice(JURISDICTIONS))
        cp_ids.append(random.choice(counterparty_ids))
        entry_dates.append(fake.date_between(start_date=date_start, end_date=date_end))
        categories.append(random.choice(ENTRY_CATEGORIES))

    df = pl.DataFrame({
        "entry_id": entry_ids,
        "token_id": token_ids,
        "account_ref": account_refs,
        "entity_name": entity_names,
        "amount": amounts,
        "jurisdiction": jurisdictions,
        "counterparty_id": cp_ids,
        "entry_date": entry_dates,
        "category": categories,
    })
    logger.info("ledger_entries generated: %d rows", len(df))
    return df


def generate_entities(*, seed: int = DATA_SEED) -> pl.DataFrame:
    """Generate 50K entity rows for Snowflake."""
    fake = Faker()
    Faker.seed(seed)
    random.seed(seed)

    logger.info("Generating entities (%d rows) ...", ENTITY_ROWS)

    entity_ids: list[int] = []
    entity_names: list[str] = []
    account_refs: list[str] = []
    jurisdictions: list[str] = []
    entity_types: list[str] = []
    created_dates: list[date] = []

    for i in range(ENTITY_ROWS):
        entity_ids.append(i + 1)
        etype = random.choice(ENTITY_TYPES)
        entity_types.append(etype)
        if etype == "corporate":
            entity_names.append(fake.company())
        else:
            entity_names.append(fake.name())
        account_refs.append(f"REF-{fake.bothify(text='???-########', letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ')}")
        jurisdictions.append(random.choice(JURISDICTIONS))
        created_dates.append(fake.date_between(start_date=date(2018, 1, 1), end_date=date(2025, 12, 31)))

    df = pl.DataFrame({
        "entity_id": entity_ids,
        "entity_name": entity_names,
        "account_ref": account_refs,
        "jurisdiction": jurisdictions,
        "entity_type": entity_types,
        "created_date": created_dates,
    })
    logger.info("entities generated: %d rows", len(df))
    return df


def generate_risk_signals(
    entry_ids: list[int],
    *,
    seed: int = DATA_SEED,
) -> pl.DataFrame:
    """Generate 100K risk-signal rows referencing ledger entry IDs."""
    fake = Faker()
    Faker.seed(seed)
    random.seed(seed)

    logger.info("Generating risk_signals (%d rows) ...", RISK_ROWS)

    signal_ids: list[int] = []
    ref_entry_ids: list[int] = []
    risk_scores: list[float] = []
    signal_types: list[str] = []
    detected_dates: list[date] = []

    for i in range(RISK_ROWS):
        signal_ids.append(i + 1)
        ref_entry_ids.append(random.choice(entry_ids))
        risk_scores.append(round(random.uniform(0.0, 1.0), 4))
        signal_types.append(random.choice(SIGNAL_TYPES))
        detected_dates.append(fake.date_between(start_date=date(2023, 1, 1), end_date=date(2025, 12, 31)))

    df = pl.DataFrame({
        "signal_id": signal_ids,
        "entry_id": ref_entry_ids,
        "risk_score": risk_scores,
        "signal_type": signal_types,
        "detected_date": detected_dates,
    })
    logger.info("risk_signals generated: %d rows", len(df))
    return df


# ===================================================================
# LOADERS
# ===================================================================

def _redshift_connection() -> Any:
    """Return a psycopg2 connection to Redshift Serverless."""
    import psycopg2

    host = os.getenv("REDSHIFT_HOST", "")
    port = int(os.getenv("REDSHIFT_PORT", "5439"))
    database = os.getenv("REDSHIFT_DATABASE", "dev")
    user = os.getenv("REDSHIFT_USER", "admin")
    password = os.getenv("REDSHIFT_PASSWORD", "")

    logger.info("Connecting to Redshift %s:%d/%s as %s ...", host, port, database, user)
    conn = psycopg2.connect(
        host=host,
        port=port,
        dbname=database,
        user=user,
        password=password,
        sslmode="require",
        connect_timeout=30,
    )
    conn.autocommit = True
    return conn


def load_redshift_hot(df: pl.DataFrame) -> dict[str, Any]:
    """Load ledger_entries_hot into Redshift federation.ledger_entries.

    Uses COPY via S3 for speed: write CSV to S3, then COPY.
    Falls back to batched INSERT if S3 COPY fails.
    """
    import boto3
    import psycopg2

    conn = _redshift_connection()
    try:
        cur = conn.cursor()

        # Ensure schema exists
        cur.execute("CREATE SCHEMA IF NOT EXISTS federation;")

        # Create table
        ddl = redshift_create_table_ddl(
            "federation",
            "ledger_entries",
            LEDGER_ENTRIES_COLUMNS,
            diststyle="KEY",
            distkey="entry_id",
            sortkey="entry_date",
        )
        # Drop and recreate for idempotency
        cur.execute("DROP TABLE IF EXISTS federation.ledger_entries;")
        cur.execute(ddl)
        logger.info("Redshift table federation.ledger_entries created")

        # Strategy: write CSV to S3, then COPY
        bucket = os.getenv("S3_BUCKET", "")
        s3_key = "staging/ledger_entries_hot.csv"
        iam_role = os.getenv("SPECTRUM_ROLE_ARN", "")

        # Validate inputs before attempting S3 COPY — validation failures
        # should not silently fall back to batched INSERT.
        s3_copy_viable = True
        try:
            validate_s3_bucket(bucket)
            validate_iam_role_arn(iam_role)
        except ValueError:
            s3_copy_viable = False
            logger.info("S3 COPY not configured (missing bucket or IAM role), using batched INSERT")

        if s3_copy_viable:
            try:
                logger.info("Writing CSV to s3://%s/%s for COPY ...", bucket, s3_key)
                # Polars write_csv to bytes — no header for COPY
                df_for_csv = df.with_columns(
                    pl.col("entry_date").cast(pl.Utf8),
                )
                csv_result = df_for_csv.write_csv(include_header=False)
                csv_bytes = csv_result.encode("utf-8") if isinstance(csv_result, str) else csv_result

                s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION", "us-east-2"))
                s3.put_object(Bucket=bucket, Key=s3_key, Body=csv_bytes)
                logger.info("CSV uploaded to S3 (%d bytes)", len(csv_bytes))

                copy_sql = f"""
                    COPY federation.ledger_entries
                    FROM 's3://{bucket}/{s3_key}'
                    IAM_ROLE '{iam_role}'
                    CSV
                    DATEFORMAT 'auto'
                    MAXERROR 100
                    TRUNCATECOLUMNS;
                """
                cur.execute(copy_sql)
                logger.info("COPY complete")

                # Clean up staging file
                s3.delete_object(Bucket=bucket, Key=s3_key)
            except Exception as copy_err:
                logger.warning("S3 COPY failed (%s), falling back to batched INSERT ...", copy_err)
                _redshift_batched_insert(cur, df, "federation.ledger_entries")
        else:
            _redshift_batched_insert(cur, df, "federation.ledger_entries")

        # Verify
        cur.execute("SELECT COUNT(*) FROM federation.ledger_entries;")
        count = cur.fetchone()[0]
        logger.info("Redshift federation.ledger_entries row count: %d", count)

        cur.close()
        return {"rows": count, "status": "loaded"}
    finally:
        conn.close()


def _redshift_batched_insert(cur: Any, df: pl.DataFrame, table: str) -> None:
    """Insert rows in batches using multi-row VALUES.

    Note: ``table`` must be a trusted, internally-constructed qualified name
    (e.g. ``"federation.ledger_entries"``). Each component is validated.
    """
    import psycopg2.extras

    # Validate each component of the qualified table name
    for part in table.split("."):
        validate_identifier(part)

    rows = df.rows()
    total = len(rows)
    col_names = df.columns
    placeholders = ", ".join(["%s"] * len(col_names))
    insert_sql = f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({placeholders})"

    for start in range(0, total, BATCH_SIZE):
        batch = rows[start : start + BATCH_SIZE]
        # Convert date objects for psycopg2
        cleaned_batch = []
        for row in batch:
            cleaned_row = []
            for val in row:
                if isinstance(val, date) and not isinstance(val, datetime):
                    cleaned_row.append(val.isoformat())
                else:
                    cleaned_row.append(val)
            cleaned_batch.append(tuple(cleaned_row))
        psycopg2.extras.execute_batch(cur, insert_sql, cleaned_batch, page_size=1000)
        loaded = min(start + BATCH_SIZE, total)
        if loaded % 50_000 == 0 or loaded == total:
            logger.info("  Redshift INSERT progress: %d / %d", loaded, total)


def load_s3_parquet(
    df: pl.DataFrame,
    s3_prefix: str,
    *,
    filename: str = "data.parquet",
) -> str:
    """Write a Polars DataFrame to S3 as Parquet. Returns the full S3 path."""
    import boto3

    bucket = os.getenv("S3_BUCKET", "")
    validate_s3_bucket(bucket)
    s3_key = f"{s3_prefix}{filename}"
    full_path = f"s3://{bucket}/{s3_key}"

    logger.info("Writing Parquet to %s ...", full_path)

    # Write to a temp file, then upload
    with tempfile.NamedTemporaryFile(suffix=".parquet", delete=True) as tmp:
        df.write_parquet(tmp.name, use_pyarrow=True)
        tmp.seek(0)
        s3 = boto3.client("s3", region_name=os.getenv("AWS_REGION", "us-east-2"))
        s3.upload_file(tmp.name, bucket, s3_key)

    logger.info("Parquet uploaded: %s (%d rows)", full_path, len(df))
    return full_path


def ensure_glue_table(
    table_name: str,
    s3_location: str,
    columns: Any,
) -> None:
    """Create or update a Glue table pointing to S3 Parquet data."""
    import boto3

    glue = boto3.client("glue", region_name=os.getenv("AWS_REGION", "us-east-2"))
    glue_db = os.getenv("GLUE_DATABASE", "federation_demo")

    glue_cols = glue_columns(columns)

    table_input: dict[str, Any] = {
        "Name": table_name,
        "StorageDescriptor": {
            "Columns": glue_cols,
            "Location": s3_location,
            "InputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
            "SerdeInfo": {
                "SerializationLibrary": "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe",
            },
        },
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {
            "classification": "parquet",
            "has_encrypted_data": "false",
        },
    }

    try:
        glue.delete_table(DatabaseName=glue_db, Name=table_name)
        logger.info("Deleted existing Glue table %s.%s", glue_db, table_name)
    except glue.exceptions.EntityNotFoundException:
        pass

    glue.create_table(DatabaseName=glue_db, TableInput=table_input)
    logger.info("Glue table %s.%s created -> %s", glue_db, table_name, s3_location)


def load_spectrum_warm(df: pl.DataFrame) -> dict[str, Any]:
    """Write warm ledger entries to S3 Parquet and register in Glue for Spectrum."""
    bucket = os.getenv("S3_BUCKET", "")
    validate_s3_bucket(bucket)
    s3_prefix = "spectrum/ledger_entries_warm/"
    s3_location = f"s3://{bucket}/{s3_prefix}"

    # Write Parquet
    load_s3_parquet(df, s3_prefix, filename="data.parquet")

    # Register Glue table
    ensure_glue_table("ledger_entries_warm", s3_location, LEDGER_ENTRIES_COLUMNS)

    return {"rows": len(df), "status": "loaded", "path": s3_location}


def load_counterparty_ref_s3(df: pl.DataFrame) -> dict[str, Any]:
    """Write counterparty_ref to S3 Parquet and register in Glue for Spectrum."""
    bucket = os.getenv("S3_BUCKET", "")
    validate_s3_bucket(bucket)
    s3_prefix = "spectrum/counterparty_ref/"
    s3_location = f"s3://{bucket}/{s3_prefix}"

    load_s3_parquet(df, s3_prefix, filename="data.parquet")
    ensure_glue_table("counterparty_ref", s3_location, COUNTERPARTY_REF_COLUMNS)

    return {"rows": len(df), "status": "loaded", "path": s3_location}


def load_snowflake_entities(df: pl.DataFrame) -> dict[str, Any]:
    """Load entities into Snowflake FEDERATION_DEMO.PUBLIC.ENTITIES."""
    import snowflake.connector

    account = os.getenv("SNOWFLAKE_ACCOUNT", "")
    user = os.getenv("SNOWFLAKE_USER", "")
    password = os.getenv("SNOWFLAKE_PASSWORD", "")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE", "")
    database = os.getenv("SNOWFLAKE_DATABASE", "")
    role = os.getenv("SNOWFLAKE_ROLE", "")

    logger.info("Connecting to Snowflake %s as %s ...", account, user)
    conn = snowflake.connector.connect(
        account=account,
        user=user,
        password=password,
        warehouse=warehouse,
        database=database,
        role=role or None,
        schema="PUBLIC",
    )
    try:
        cur = conn.cursor()

        # Create database/schema if needed
        validate_identifier(database)
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {database};")
        cur.execute(f"USE DATABASE {database};")
        cur.execute("CREATE SCHEMA IF NOT EXISTS PUBLIC;")
        cur.execute("USE SCHEMA PUBLIC;")

        # Create table
        ddl = snowflake_create_table_ddl(database, "PUBLIC", "ENTITIES", ENTITIES_COLUMNS)
        cur.execute(f"DROP TABLE IF EXISTS {database}.PUBLIC.ENTITIES;")
        cur.execute(ddl)
        logger.info("Snowflake table %s.PUBLIC.ENTITIES created", database)

        # Use PUT + COPY for bulk load — write CSV to temp, PUT to stage, COPY
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, prefix="entities_"
        ) as tmp:
            tmp_path = tmp.name
            # Write CSV without header for COPY
            df_csv = df.with_columns(pl.col("created_date").cast(pl.Utf8))
            csv_str = df_csv.write_csv(include_header=False)
            tmp.write(csv_str)

        try:
            cur.execute("CREATE OR REPLACE TEMPORARY STAGE entities_stage FILE_FORMAT = (TYPE = 'CSV' FIELD_OPTIONALLY_ENCLOSED_BY = '\"');")
            cur.execute(f"PUT 'file://{tmp_path}' @entities_stage AUTO_COMPRESS=TRUE;")
            logger.info("PUT to Snowflake stage complete")

            cur.execute(f"""
                COPY INTO {database}.PUBLIC.ENTITIES
                FROM @entities_stage
                FILE_FORMAT = (TYPE = 'CSV' FIELD_OPTIONALLY_ENCLOSED_BY = '\"')
                ON_ERROR = 'CONTINUE';
            """)
            logger.info("Snowflake COPY INTO complete")
        finally:
            os.unlink(tmp_path)

        # Verify (database already validated above)
        cur.execute(f"SELECT COUNT(*) FROM {database}.PUBLIC.ENTITIES;")
        count = cur.fetchone()[0]
        logger.info("Snowflake ENTITIES row count: %d", count)

        cur.close()
        return {"rows": count, "status": "loaded"}
    finally:
        conn.close()


def load_databricks_risk_signals(df: pl.DataFrame) -> dict[str, Any]:
    """Attempt to load risk_signals into Databricks Unity Catalog.

    Falls back to local CSV if write access is unavailable.
    """
    host = os.getenv("DATABRICKS_HOST", "")
    token = os.getenv("DATABRICKS_TOKEN", "")
    catalog = os.getenv("DATABRICKS_CATALOG", "")

    if not host or not token:
        logger.warning("Databricks credentials not configured — saving CSV locally")
        return _save_risk_signals_csv(df, reason="no credentials")

    try:
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.service.catalog import VolumeType

        logger.info("Connecting to Databricks %s ...", host)
        ws = WorkspaceClient(host=host, token=token)

        # Try to create schema and table
        schema_name = "federation_demo"
        table_name = "risk_signals"

        try:
            ws.schemas.create(name=schema_name, catalog_name=catalog, comment="Federation demo schema")
            logger.info("Created Databricks schema %s.%s", catalog, schema_name)
        except Exception as schema_err:
            logger.info("Schema create result: %s", schema_err)

        # Try uploading via Databricks SQL Statement API
        # Write CSV to a volume, then CREATE TABLE from it
        try:
            # Create a volume for staging
            volume_name = "federation_staging"
            try:
                ws.volumes.create(
                    catalog_name=catalog,
                    schema_name=schema_name,
                    name=volume_name,
                    volume_type=VolumeType.MANAGED,
                )
                logger.info("Created volume %s.%s.%s", catalog, schema_name, volume_name)
            except Exception as vol_err:
                logger.info("Volume create result: %s", vol_err)

            # Upload CSV to volume
            csv_content = df.with_columns(
                pl.col("detected_date").cast(pl.Utf8),
            ).write_csv(include_header=True).encode("utf-8")

            volume_path = f"/Volumes/{catalog}/{schema_name}/{volume_name}/risk_signals.csv"
            ws.files.upload(volume_path, io.BytesIO(csv_content), overwrite=True)
            logger.info("Uploaded CSV to Databricks volume: %s", volume_path)

            # Create table from CSV using SQL
            sql_statement = f"""
                CREATE OR REPLACE TABLE {catalog}.{schema_name}.{table_name}
                USING CSV
                OPTIONS (header 'true', inferSchema 'true')
                LOCATION '{volume_path}'
            """
            # Use the statement execution API
            warehouses = ws.warehouses.list()
            warehouse_id = None
            for wh in warehouses:
                warehouse_id = wh.id
                break

            if warehouse_id:
                from databricks.sdk.service.sql import StatementState

                def _exec_sql(sql: str, *, timeout: str = "50s") -> Any:
                    """Execute SQL on Databricks, polling if result not ready."""
                    resp = ws.statement_execution.execute_statement(
                        warehouse_id=warehouse_id,
                        statement=sql,
                        wait_timeout=timeout,
                    )
                    if resp.status and resp.status.state in (
                        StatementState.PENDING,
                        StatementState.RUNNING,
                    ):
                        import time as _time
                        for _ in range(60):
                            _time.sleep(5)
                            resp = ws.statement_execution.get_statement(resp.statement_id)
                            if resp.status.state not in (
                                StatementState.PENDING,
                                StatementState.RUNNING,
                            ):
                                break
                    if resp.status and resp.status.state == StatementState.FAILED:
                        raise RuntimeError(f"SQL failed: {resp.status.error}")
                    return resp

                validate_identifier(catalog)
                validate_identifier(schema_name)
                validate_identifier(table_name)
                _exec_sql(f"CREATE SCHEMA IF NOT EXISTS {catalog}.{schema_name}")
                _exec_sql(f"""
                    CREATE OR REPLACE TABLE {catalog}.{schema_name}.{table_name} (
                        signal_id BIGINT,
                        entry_id BIGINT,
                        risk_score DOUBLE,
                        signal_type STRING,
                        detected_date DATE
                    )
                """)
                logger.info("Created table %s.%s.%s", catalog, schema_name, table_name)

                # Insert in batches via SQL (2000 rows per batch)
                # Values are self-generated (seed=42) so injection risk is low,
                # but we still sanitise string values as a defensive measure.
                rows = df.rows()
                for start in range(0, len(rows), 2000):
                    batch = rows[start:start + 2000]
                    values_parts = []
                    for row in batch:
                        sid, eid, rscore, stype, ddate = row
                        ddate_str = ddate.isoformat() if hasattr(ddate, 'isoformat') else str(ddate)
                        safe_stype = str(stype).replace("'", "''")
                        safe_ddate = str(ddate_str).replace("'", "''")
                        values_parts.append(
                            f"({sid}, {eid}, {rscore}, '{safe_stype}', '{safe_ddate}')"
                        )
                    insert_sql = (
                        f"INSERT INTO {catalog}.{schema_name}.{table_name} "
                        f"VALUES {', '.join(values_parts)}"
                    )
                    _exec_sql(insert_sql)
                    loaded = min(start + 2000, len(rows))
                    if loaded % 20_000 == 0 or loaded == len(rows):
                        logger.info("  Databricks INSERT progress: %d / %d", loaded, len(rows))

                # Verify
                verify = _exec_sql(
                    f"SELECT COUNT(*) FROM {catalog}.{schema_name}.{table_name}"
                )
                if verify.result and verify.result.data_array:
                    count = int(verify.result.data_array[0][0])
                    logger.info("Databricks %s.%s.%s row count: %d", catalog, schema_name, table_name, count)
                    return {"rows": count, "status": "loaded"}

            logger.warning("No SQL warehouse available, falling back to CSV")
            return _save_risk_signals_csv(df, reason="no SQL warehouse")

        except Exception as table_err:
            logger.warning("Databricks table creation failed: %s", table_err)
            return _save_risk_signals_csv(df, reason=str(table_err))

    except Exception as db_err:
        logger.warning("Databricks connection failed: %s", db_err)
        return _save_risk_signals_csv(df, reason=str(db_err))


def _save_risk_signals_csv(df: pl.DataFrame, *, reason: str) -> dict[str, Any]:
    """Save risk_signals as local CSV fallback.

    # SIMULATION NOTE: Databricks write access not available — data saved locally.
    """
    csv_path = DATA_DIR / "csv" / "risk_signals.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    df.write_csv(csv_path)
    logger.info(
        "risk_signals saved to %s (%d rows) — reason: %s",
        csv_path,
        len(df),
        reason,
    )
    return {
        "rows": len(df),
        "status": "csv_fallback",
        "path": str(csv_path),
        "reason": reason,
    }


def load_iceberg_cold(df: pl.DataFrame) -> dict[str, Any]:
    """Write cold-tier ledger entries to S3 as Iceberg V2 table.

    Uses PyIceberg to create an Iceberg table with Glue as catalog backend.
    Falls back to Parquet-on-S3 with Glue registration if PyIceberg is unavailable.

    The Iceberg table is registered at:
      s3://{bucket}/iceberg/federation_demo/ledger_entries_cold/

    SIMULATION NOTE: If PyIceberg or Glue access is unavailable, the data is
    written as Parquet to S3 and registered in Glue with Iceberg-compatible
    metadata so that Trino's Iceberg connector can read it.
    """
    bucket = os.getenv("S3_BUCKET", "")
    validate_s3_bucket(bucket)
    glue_db = os.getenv("GLUE_DATABASE", "federation_demo")
    s3_prefix = "iceberg/federation_demo/ledger_entries_cold/"
    s3_location = f"s3://{bucket}/{s3_prefix}"

    try:
        # Attempt native PyIceberg write
        from pyiceberg.catalog import load_catalog

        catalog = load_catalog(
            "glue",
            **{
                "type": "glue",
                "glue.region": os.getenv("AWS_REGION", "us-east-2"),
                "warehouse": f"s3://{bucket}/iceberg/",
            },
        )

        # Convert Polars -> PyArrow for Iceberg write
        arrow_table = df.to_arrow()

        table_id = f"{glue_db}.ledger_entries_cold"
        try:
            ice_table = catalog.load_table(table_id)
            ice_table.overwrite(arrow_table)
            logger.info("Overwrote existing Iceberg table %s", table_id)
        except Exception:
            import pyarrow as pa

            ice_table = catalog.create_table(
                table_id,
                schema=arrow_table.schema,
                location=s3_location,
            )
            ice_table.overwrite(arrow_table)
            logger.info("Created Iceberg table %s at %s", table_id, s3_location)

        return {"rows": len(df), "status": "loaded", "format": "iceberg", "path": s3_location}

    except ImportError:
        logger.warning("PyIceberg not available — falling back to Parquet + Glue registration")
    except Exception as ice_err:
        logger.warning("Iceberg write failed (%s) — falling back to Parquet + Glue registration", ice_err)

    # Fallback: write as Parquet and register in Glue with Iceberg-style metadata
    load_s3_parquet(df, s3_prefix, filename="data.parquet")
    _register_glue_iceberg_table(
        "ledger_entries_cold", s3_location, LEDGER_ENTRIES_COLUMNS
    )
    return {"rows": len(df), "status": "loaded_parquet_fallback", "format": "parquet_as_iceberg", "path": s3_location}


def load_open_catalog_entities(df: pl.DataFrame) -> dict[str, Any]:
    """Write entities to Snowflake Open Catalog as Iceberg table via PyIceberg REST.

    The Open Catalog (Polaris) instance provides an Iceberg REST catalog that
    Gravitino can introspect. This gives Gravitino a Discover path for Snowflake
    data — the native Snowflake ENTITIES table is accessed via Trino's Snowflake
    connector for queries, while this Iceberg copy enables catalog-level discovery.

    SIMULATION NOTE: This is a separate Iceberg copy of the entities data, not
    the live Snowflake native table. It demonstrates the Discover path through
    Gravitino for Snowflake-managed datasets via Open Catalog.
    """
    from pyiceberg.catalog import load_catalog

    oc_account = os.getenv("SNOWFLAKE_OPEN_CATALOG_ACCOUNT", "")
    client_id = os.getenv("SNOWFLAKE_OPEN_CATALOG_CLIENT_ID", "")
    client_secret = os.getenv("SNOWFLAKE_OPEN_CATALOG_CLIENT_SECRET", "")
    oc_catalog = os.getenv("SNOWFLAKE_OPEN_CATALOG_CATALOG", "federation_demo")

    if not oc_account or not client_id or not client_secret:
        logger.warning("Open Catalog credentials not configured — skipping")
        return {"rows": 0, "status": "skipped", "reason": "no credentials"}

    logger.info("Connecting to Snowflake Open Catalog %s ...", oc_account)
    catalog = load_catalog("polaris", **{
        "type": "rest",
        "uri": f"https://{oc_account}.snowflakecomputing.com/polaris/api/catalog",
        "credential": f"{client_id}:{client_secret}",
        "warehouse": oc_catalog,
        "scope": "PRINCIPAL_ROLE:ALL",
    })

    arrow_table = df.to_arrow()
    table_id = "public.entities"

    try:
        ice_table = catalog.load_table(table_id)
        ice_table.overwrite(arrow_table)
        logger.info("Overwrote existing Iceberg table %s in Open Catalog", table_id)
    except Exception:
        ice_table = catalog.create_table(table_id, schema=arrow_table.schema)
        ice_table.overwrite(arrow_table)
        logger.info("Created Iceberg table %s in Open Catalog", table_id)

    return {"rows": len(df), "status": "loaded", "format": "iceberg", "catalog": "open_catalog"}


def _register_glue_iceberg_table(
    table_name: str,
    s3_location: str,
    columns: Any,
) -> None:
    """Register a Glue table with Iceberg-compatible metadata.

    SIMULATION NOTE: This registers the table in Glue so Trino's Iceberg
    connector can find it. The actual Iceberg metadata files may be absent
    if PyIceberg was unavailable.
    """
    import boto3

    glue = boto3.client("glue", region_name=os.getenv("AWS_REGION", "us-east-2"))
    glue_db = os.getenv("GLUE_DATABASE", "federation_demo")

    glue_cols = glue_columns(columns)

    table_input: dict[str, Any] = {
        "Name": table_name,
        "StorageDescriptor": {
            "Columns": glue_cols,
            "Location": s3_location,
            "InputFormat": "org.apache.iceberg.mr.mapred.IcebergInputFormat",
            "OutputFormat": "org.apache.iceberg.mr.mapred.IcebergOutputFormat",
            "SerdeInfo": {
                "SerializationLibrary": "org.apache.iceberg.mr.serde.IcebergSerDe",
            },
        },
        "TableType": "EXTERNAL_TABLE",
        "Parameters": {
            "table_type": "ICEBERG",
            "classification": "iceberg",
            "has_encrypted_data": "false",
            "metadata_location": f"{s3_location}metadata/00000-initial.metadata.json",
        },
    }

    try:
        glue.delete_table(DatabaseName=glue_db, Name=table_name)
        logger.info("Deleted existing Glue table %s.%s", glue_db, table_name)
    except glue.exceptions.EntityNotFoundException:
        pass

    glue.create_table(DatabaseName=glue_db, TableInput=table_input)
    logger.info("Glue Iceberg table %s.%s created -> %s", glue_db, table_name, s3_location)


# ===================================================================
# LOCAL PARQUET BACKUP (for reproducibility)
# ===================================================================

def save_local_parquet(df: pl.DataFrame, name: str) -> Path:
    """Save a DataFrame as local Parquet for offline use."""
    out_dir = DATA_DIR / "parquet"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.parquet"
    df.write_parquet(path, use_pyarrow=True)
    logger.info("Local Parquet saved: %s (%d rows)", path, len(df))
    return path


# ===================================================================
# CONTRACT OUTPUT
# ===================================================================

def write_contract(table_results: dict[str, dict[str, Any]]) -> Path:
    """Write the datagen contract JSON."""
    CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)
    contract = {
        "agent": "datagen",
        "status": "complete",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "tables": table_results,
            "seed": DATA_SEED,
            "sanitized_columns": True,
        },
    }
    path = CONTRACTS_DIR / "data-loaded.json"
    path.write_text(json.dumps(contract, indent=2, default=str))
    logger.info("Contract written: %s", path)
    return path


# ===================================================================
# MAIN ORCHESTRATOR
# ===================================================================

def run_all() -> dict[str, dict[str, Any]]:
    """Generate all data and load to every platform. Returns table results."""
    load_dotenv(PROJECT_ROOT / ".env")
    start = time.time()
    results: dict[str, dict[str, Any]] = {}

    # ── 1. Counterparty ref (needed for FK references) ────────────
    logger.info("=" * 60)
    logger.info("PHASE 1: Generating counterparty_ref")
    logger.info("=" * 60)
    cp_df = generate_counterparty_ref()
    save_local_parquet(cp_df, "counterparty_ref")
    cp_ids = cp_df["counterparty_id"].to_list()

    try:
        results["s3.spectrum.counterparty_ref"] = load_counterparty_ref_s3(cp_df)
    except Exception as err:
        logger.error("Failed to load counterparty_ref to S3: %s", err)
        results["s3.spectrum.counterparty_ref"] = {"rows": 0, "status": "failed", "error": str(err)}

    # ── 2. Ledger entries HOT (recent dates, Redshift) ────────────
    logger.info("=" * 60)
    logger.info("PHASE 2: Generating ledger_entries_hot")
    logger.info("=" * 60)
    hot_df = generate_ledger_entries(
        cp_ids,
        n_rows=HOT_ROWS,
        date_start=date(2024, 1, 1),
        date_end=date(2025, 12, 31),
        seed=DATA_SEED,
        id_offset=0,
    )
    save_local_parquet(hot_df, "ledger_entries_hot")

    try:
        results["redshift.federation.ledger_entries"] = load_redshift_hot(hot_df)
    except Exception as err:
        logger.error("Failed to load ledger_entries_hot to Redshift: %s", err)
        results["redshift.federation.ledger_entries"] = {"rows": 0, "status": "failed", "error": str(err)}

    # ── 3. Ledger entries WARM (older dates, S3/Spectrum) ─────────
    logger.info("=" * 60)
    logger.info("PHASE 3: Generating ledger_entries_warm")
    logger.info("=" * 60)
    warm_df = generate_ledger_entries(
        cp_ids,
        n_rows=WARM_ROWS,
        date_start=date(2020, 1, 1),
        date_end=date(2023, 12, 31),
        seed=DATA_SEED + WARM_SEED_OFFSET,  # Different seed so data differs from hot
        id_offset=HOT_ROWS,   # IDs continue from hot
    )
    save_local_parquet(warm_df, "ledger_entries_warm")

    try:
        results["s3.spectrum.ledger_entries_warm"] = load_spectrum_warm(warm_df)
    except Exception as err:
        logger.error("Failed to load ledger_entries_warm to S3: %s", err)
        results["s3.spectrum.ledger_entries_warm"] = {"rows": 0, "status": "failed", "error": str(err)}

    # ── 3b. Ledger entries COLD (archive dates, S3/Iceberg) ───────
    logger.info("=" * 60)
    logger.info("PHASE 3b: Generating ledger_entries_cold (Iceberg)")
    logger.info("=" * 60)
    cold_df = generate_ledger_entries(
        cp_ids,
        n_rows=COLD_ROWS,
        date_start=date(2018, 1, 1),
        date_end=date(2019, 12, 31),
        seed=DATA_SEED + COLD_SEED_OFFSET,
        id_offset=HOT_ROWS + WARM_ROWS,
    )
    save_local_parquet(cold_df, "ledger_entries_cold")

    try:
        results["s3.iceberg.ledger_entries_cold"] = load_iceberg_cold(cold_df)
    except Exception as err:
        logger.error("Failed to load ledger_entries_cold to Iceberg: %s", err)
        results["s3.iceberg.ledger_entries_cold"] = {"rows": 0, "status": "failed", "error": str(err)}

    # ── 4. Entities (Snowflake) ───────────────────────────────────
    logger.info("=" * 60)
    logger.info("PHASE 4: Generating entities")
    logger.info("=" * 60)
    ent_df = generate_entities()
    save_local_parquet(ent_df, "entities")

    try:
        results["snowflake.FEDERATION_DEMO.PUBLIC.ENTITIES"] = load_snowflake_entities(ent_df)
    except Exception as err:
        logger.error("Failed to load entities to Snowflake: %s", err)
        results["snowflake.FEDERATION_DEMO.PUBLIC.ENTITIES"] = {"rows": 0, "status": "failed", "error": str(err)}

    # ── 4b. Entities (Snowflake Open Catalog / Iceberg) ────────────
    # Separate Iceberg copy for Gravitino Discover path — the native
    # Snowflake table is queried via Trino's Snowflake connector.
    if os.getenv("SNOWFLAKE_OPEN_CATALOG_ACCOUNT"):
        logger.info("=" * 60)
        logger.info("PHASE 4b: Loading entities to Snowflake Open Catalog (Iceberg)")
        logger.info("=" * 60)
        try:
            results["snowflake_open_catalog.entities"] = load_open_catalog_entities(ent_df)
        except Exception as err:
            logger.error("Failed to load entities to Open Catalog: %s", err)
            results["snowflake_open_catalog.entities"] = {"rows": 0, "status": "failed", "error": str(err)}

    # ── 5. Risk signals (Databricks or local CSV) ─────────────────
    logger.info("=" * 60)
    logger.info("PHASE 5: Generating risk_signals")
    logger.info("=" * 60)
    # FK references: use entry_ids from both hot and warm
    all_entry_ids = hot_df["entry_id"].to_list() + warm_df["entry_id"].to_list()
    risk_df = generate_risk_signals(all_entry_ids)
    save_local_parquet(risk_df, "risk_signals")

    try:
        results["databricks.risk_signals"] = load_databricks_risk_signals(risk_df)
    except Exception as err:
        logger.error("Failed to load risk_signals: %s", err)
        results["databricks.risk_signals"] = _save_risk_signals_csv(risk_df, reason=str(err))

    # ── Contract ──────────────────────────────────────────────────
    write_contract(results)

    elapsed = time.time() - start
    logger.info("=" * 60)
    logger.info("ALL DONE in %.1f seconds", elapsed)
    for table_name, info in results.items():
        logger.info("  %-50s %s  rows=%s", table_name, info.get("status"), info.get("rows"))
    logger.info("=" * 60)

    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    run_all()
