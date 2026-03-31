"""Governance comparison matrix — the key demo artifact.

Compares governed (Trino + Ranger) vs ungoverned (direct platform) data access
paths side by side. For each path, records row count, visible columns, latency,
and which governance layer (if any) was active.

The comparison matrix is the centrepiece of the governance-comparison notebook.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import polars as pl
from dotenv import load_dotenv

from src.utils.config import TRINO_USER
from src.utils.sql_safety import validate_identifier, validate_non_negative_int

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

QUERY_LIMIT: int = 10_000  # Cap row fetches for demo speed


@dataclass
class PathResult:
    """Result from a single data access path."""

    path_name: str
    governance_layer: str
    row_count: int = 0
    columns_visible: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    error: str | None = None


# ---------------------------------------------------------------------------
# Individual path executors
# ---------------------------------------------------------------------------

def _query_trino_redshift(limit: int = QUERY_LIMIT) -> PathResult:
    """Query Redshift ledger_entries through Trino (Ranger-governed path).

    This is the GOVERNED path: Trino executes the query, and Ranger enforces
    access policies at the federation layer.
    """
    import trino

    host = os.getenv("TRINO_HOST", "")
    port = int(os.getenv("TRINO_PORT", "8080"))

    result = PathResult(
        path_name="trino_redshift",
        governance_layer="ranger",
    )

    conn = None
    try:
        conn = trino.dbapi.connect(
            host=host,
            port=port,
            user=TRINO_USER,
            catalog="redshift",
            schema="federation",
        )
        cursor = conn.cursor()

        start = time.perf_counter()
        cursor.execute(
            f"SELECT * FROM redshift.federation.ledger_entries LIMIT {validate_non_negative_int(limit)}"
        )
        rows = cursor.fetchall()
        elapsed = time.perf_counter() - start

        # Column names from cursor description
        columns = [desc[0] for desc in cursor.description] if cursor.description else []

        result.row_count = len(rows)
        result.columns_visible = columns
        result.latency_ms = round(elapsed * 1000, 2)

        logger.info(
            "Trino→Redshift: %d rows, %d cols, %.1f ms",
            result.row_count,
            len(columns),
            result.latency_ms,
        )

    except Exception as exc:  # Intentional broad catch: path executor must not crash matrix
        result.error = str(exc)
        logger.error("Trino→Redshift path failed: %s", exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    return result


def _query_direct_redshift(limit: int = QUERY_LIMIT) -> PathResult:
    """Query Redshift ledger_entries directly via psycopg2 (ungoverned path).

    This path bypasses the Trino federation layer entirely. No Ranger policy
    enforcement. Access relies solely on Redshift-native RBAC (Tier 1).
    """
    import psycopg2

    host = os.getenv("REDSHIFT_HOST", "")
    port = int(os.getenv("REDSHIFT_PORT", "5439"))
    database = os.getenv("REDSHIFT_DATABASE", "dev")
    user = os.getenv("REDSHIFT_USER", "")
    password = os.getenv("REDSHIFT_PASSWORD", "")

    result = PathResult(
        path_name="direct_redshift",
        governance_layer="platform_native",
    )

    conn = None
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=database,
            user=user,
            password=password,
            sslmode="require",
        )
        cursor = conn.cursor()

        start = time.perf_counter()
        cursor.execute(
            f"SELECT * FROM federation.ledger_entries LIMIT {validate_non_negative_int(limit)}"
        )
        rows = cursor.fetchall()
        elapsed = time.perf_counter() - start

        columns = [desc[0] for desc in cursor.description] if cursor.description else []

        result.row_count = len(rows)
        result.columns_visible = columns
        result.latency_ms = round(elapsed * 1000, 2)

        logger.info(
            "Direct→Redshift: %d rows, %d cols, %.1f ms",
            result.row_count,
            len(columns),
            result.latency_ms,
        )

    except Exception as exc:  # Intentional broad catch: path executor must not crash matrix
        result.error = str(exc)
        logger.error("Direct→Redshift path failed: %s", exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    return result


def _read_s3_parquet(limit: int = QUERY_LIMIT) -> PathResult:
    """Read ledger_entries_warm from S3 Parquet via PyArrow (ungoverned path).

    Reads Parquet files directly from S3, bypassing all query engines.
    No governance layer is active. Relies on IAM for S3 access control.
    """
    from src.arrow.adbc_connectors import s3_arrow_reader

    result = PathResult(
        path_name="s3_parquet",
        governance_layer="iam_only",
    )

    try:
        start = time.perf_counter()
        table = s3_arrow_reader("spectrum/ledger_entries_warm/data.parquet")
        elapsed = time.perf_counter() - start

        # Apply limit after read (Parquet doesn't support LIMIT natively on read)
        if table.num_rows > limit:
            table = table.slice(0, limit)

        result.row_count = table.num_rows
        result.columns_visible = table.column_names
        result.latency_ms = round(elapsed * 1000, 2)

        logger.info(
            "S3 Parquet: %d rows, %d cols, %.1f ms",
            result.row_count,
            len(table.column_names),
            result.latency_ms,
        )

    except Exception as exc:  # Intentional broad catch: path executor must not crash matrix
        result.error = str(exc)
        logger.error("S3 Parquet path failed: %s", exc)

    return result


def _query_direct_snowflake(limit: int = QUERY_LIMIT) -> PathResult:
    """Query Snowflake ENTITIES directly (ungoverned path).

    Direct Snowflake connection. No Ranger enforcement. Access relies solely
    on Snowflake RBAC (Tier 1 platform-native governance).
    """
    import snowflake.connector

    account = os.getenv("SNOWFLAKE_ACCOUNT", "")
    user = os.getenv("SNOWFLAKE_USER", "")
    password = os.getenv("SNOWFLAKE_PASSWORD", "")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
    database = os.getenv("SNOWFLAKE_DATABASE", "FEDERATION_DEMO")
    role = os.getenv("SNOWFLAKE_ROLE", "")

    result = PathResult(
        path_name="direct_snowflake",
        governance_layer="platform_native",
    )

    conn = None
    try:
        conn = snowflake.connector.connect(
            account=account,
            user=user,
            password=password,
            warehouse=warehouse,
            database=database,
            role=role or None,
        )
        cursor = conn.cursor()

        start = time.perf_counter()
        cursor.execute(
            f"SELECT * FROM {validate_identifier(database)}.PUBLIC.ENTITIES LIMIT {validate_non_negative_int(limit)}"
        )
        rows = cursor.fetchall()
        elapsed = time.perf_counter() - start

        columns = [desc[0] for desc in cursor.description] if cursor.description else []

        result.row_count = len(rows)
        result.columns_visible = columns
        result.latency_ms = round(elapsed * 1000, 2)

        logger.info(
            "Direct→Snowflake: %d rows, %d cols, %.1f ms",
            result.row_count,
            len(columns),
            result.latency_ms,
        )

    except Exception as exc:  # Intentional broad catch: path executor must not crash matrix
        result.error = str(exc)
        logger.error("Direct→Snowflake path failed: %s", exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    return result


# ---------------------------------------------------------------------------
# Comparison matrix builder
# ---------------------------------------------------------------------------

def build_comparison_matrix(
    *,
    limit: int = QUERY_LIMIT,
    include_s3: bool = True,
) -> pl.DataFrame:
    """Build the governance comparison matrix across all data access paths.

    Executes each path sequentially, collects results, and returns a Polars
    DataFrame suitable for display in notebooks or export to JSON.

    Args:
        limit: Maximum rows to fetch per path (default 10,000).
        include_s3: Whether to include the S3 Parquet path (set False if
                    no AWS credentials available).

    Returns:
        Polars DataFrame with columns:
            path_name, governance_layer, row_count, columns_visible,
            column_count, latency_ms, status
    """
    logger.info("Building governance comparison matrix (limit=%d)", limit)

    paths: list[PathResult] = []

    # 1. Governed: Trino → Redshift (Ranger enforced)
    paths.append(_query_trino_redshift(limit=limit))

    # 2. Ungoverned: Direct Redshift (platform-native only)
    paths.append(_query_direct_redshift(limit=limit))

    # 3. Ungoverned: S3 Parquet (IAM only)
    if include_s3:
        paths.append(_read_s3_parquet(limit=limit))

    # 4. Ungoverned: Direct Snowflake (platform-native only)
    paths.append(_query_direct_snowflake(limit=limit))

    # Convert to Polars DataFrame
    records: list[dict[str, Any]] = []
    for p in paths:
        records.append({
            "path_name": p.path_name,
            "governance_layer": p.governance_layer,
            "row_count": p.row_count,
            "columns_visible": ", ".join(p.columns_visible) if p.columns_visible else "",
            "column_count": len(p.columns_visible),
            "latency_ms": p.latency_ms,
            "status": "ok" if p.error is None else "error",
            "error": p.error or "",
        })

    df = pl.DataFrame(records)
    logger.info("Comparison matrix built: %d paths", len(df))
    return df


def comparison_matrix_summary(df: pl.DataFrame) -> dict[str, Any]:
    """Extract a summary dict from the comparison matrix for reporting.

    Args:
        df: The comparison DataFrame from build_comparison_matrix().

    Returns:
        Dict with path counts, success/failure breakdown, and governance delta.
    """
    total = len(df)
    ok_count = df.filter(pl.col("status") == "ok").height
    error_count = total - ok_count

    governed = df.filter(pl.col("governance_layer") == "ranger")
    ungoverned = df.filter(pl.col("governance_layer") != "ranger")

    governed_cols = set()
    ungoverned_cols = set()

    for row in governed.iter_rows(named=True):
        if row["columns_visible"]:
            governed_cols.update(c.strip() for c in row["columns_visible"].split(","))

    for row in ungoverned.iter_rows(named=True):
        if row["columns_visible"]:
            ungoverned_cols.update(c.strip() for c in row["columns_visible"].split(","))

    return {
        "total_paths": total,
        "paths_ok": ok_count,
        "paths_error": error_count,
        "governed_paths": governed.height,
        "ungoverned_paths": ungoverned.height,
        "governed_column_count": len(governed_cols),
        "ungoverned_column_count": len(ungoverned_cols),
        "governance_delta": sorted(ungoverned_cols - governed_cols) if governed_cols else [],
    }
