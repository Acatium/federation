"""ADBC connection helpers for federated data access.

Provides thin wrappers around ADBC drivers and PyArrow for reading data
from Redshift, Trino, Snowflake, and S3 Parquet. Each function returns
either an ADBC connection or a PyArrow Table, handling missing optional
dependencies gracefully.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import pyarrow as pa
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ADBC availability checks
# ---------------------------------------------------------------------------

_ADBC_POSTGRESQL_AVAILABLE: bool = False
_ADBC_FLIGHTSQL_AVAILABLE: bool = False
_ADBC_SNOWFLAKE_AVAILABLE: bool = False

try:
    import adbc_driver_postgresql.dbapi as adbc_pg  # type: ignore[import-untyped]
    _ADBC_POSTGRESQL_AVAILABLE = True
except ImportError:
    logger.info("adbc-driver-postgresql not installed — Redshift ADBC path unavailable")

try:
    import adbc_driver_flightsql.dbapi as adbc_flight  # type: ignore[import-untyped]
    _ADBC_FLIGHTSQL_AVAILABLE = True
except ImportError:
    logger.info("adbc-driver-flightsql not installed — Trino ADBC path unavailable")

try:
    import adbc_driver_snowflake.dbapi as adbc_sf  # type: ignore[import-untyped]
    _ADBC_SNOWFLAKE_AVAILABLE = True
except ImportError:
    logger.info("adbc-driver-snowflake not installed — Snowflake ADBC path unavailable")


def adbc_postgresql_available() -> bool:
    """Return True if the ADBC PostgreSQL driver is installed."""
    return _ADBC_POSTGRESQL_AVAILABLE


def adbc_flightsql_available() -> bool:
    """Return True if the ADBC FlightSQL driver is installed."""
    return _ADBC_FLIGHTSQL_AVAILABLE


def adbc_snowflake_available() -> bool:
    """Return True if the ADBC Snowflake driver is installed."""
    return _ADBC_SNOWFLAKE_AVAILABLE


# ---------------------------------------------------------------------------
# Redshift ADBC (via PostgreSQL wire protocol)
# ---------------------------------------------------------------------------

def redshift_adbc() -> Any:
    """Return an ADBC connection to Redshift via the PostgreSQL driver.

    Raises:
        ImportError: If adbc-driver-postgresql is not installed.
        RuntimeError: If connection parameters are missing.
    """
    if not _ADBC_POSTGRESQL_AVAILABLE:
        raise ImportError(
            "adbc-driver-postgresql is required for Redshift ADBC connections"
        )

    host = os.getenv("REDSHIFT_HOST", "")
    port = os.getenv("REDSHIFT_PORT", "5439")
    database = os.getenv("REDSHIFT_DATABASE", "dev")
    user = os.getenv("REDSHIFT_USER", "")
    password = os.getenv("REDSHIFT_PASSWORD", "")

    if not host or not user:
        raise RuntimeError(
            "REDSHIFT_HOST and REDSHIFT_USER must be set in environment"
        )

    from urllib.parse import quote_plus

    uri = f"postgresql://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{database}?sslmode=require"
    logger.info("Opening ADBC PostgreSQL connection to Redshift at %s:%s", host, port)

    conn = adbc_pg.connect(uri)  # type: ignore[possibly-undefined]
    return conn


def redshift_adbc_query(sql: str) -> pa.Table:
    """Execute a SQL query against Redshift via ADBC and return a PyArrow Table.

    Args:
        sql: SQL query string.

    Returns:
        PyArrow Table with query results.
    """
    conn = redshift_adbc()
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        table = cursor.fetch_arrow_table()
        logger.info("ADBC Redshift query returned %d rows", table.num_rows)
        return table
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Trino ADBC (via FlightSQL — requires adbc-driver-flightsql)
# ---------------------------------------------------------------------------

def trino_adbc() -> Any:
    """Return an ADBC FlightSQL connection to Trino.

    Raises:
        ImportError: If adbc-driver-flightsql is not installed or Trino
                     does not expose a FlightSQL endpoint.
    """
    if not _ADBC_FLIGHTSQL_AVAILABLE:
        raise ImportError(
            "adbc-driver-flightsql is required for Trino ADBC connections"
        )

    host = os.getenv("TRINO_HOST", "")
    port = os.getenv("TRINO_PORT", "8080")

    if not host:
        raise RuntimeError("TRINO_HOST must be set in environment")

    # Trino FlightSQL would typically use a different port; community Trino
    # does not ship FlightSQL by default. We attempt the connection, but this
    # path is expected to fail in environments without Starburst Enterprise.
    uri = f"grpc://{host}:{port}"
    logger.warning(
        "Attempting Trino ADBC FlightSQL at %s — may not be available on "
        "community Trino (requires Starburst Enterprise FlightSQL endpoint)",
        uri,
    )

    conn = adbc_flight.connect(uri)  # type: ignore[possibly-undefined]
    return conn


# ---------------------------------------------------------------------------
# S3 Parquet reader via PyArrow
# ---------------------------------------------------------------------------

def s3_arrow_reader(
    s3_key: str,
    *,
    bucket: str | None = None,
    region: str | None = None,
) -> pa.Table:
    """Read a Parquet dataset from S3 directly via PyArrow.

    Args:
        s3_key: S3 key or prefix (e.g., 'spectrum/ledger_entries_warm/data.parquet').
        bucket: S3 bucket name. Defaults to S3_BUCKET env var.
        region: AWS region. Defaults to AWS_REGION env var.

    Returns:
        PyArrow Table with the Parquet data.
    """
    import pyarrow.parquet as pq
    from pyarrow.fs import S3FileSystem

    bucket = bucket or os.getenv("S3_BUCKET", "")
    region = region or os.getenv("AWS_REGION", "us-east-2")

    if not bucket:
        raise RuntimeError("S3_BUCKET must be set in environment")

    s3fs = S3FileSystem(region=region)
    s3_path = f"{bucket}/{s3_key}"

    logger.info("Reading Parquet from s3://%s (region=%s)", s3_path, region)

    table = pq.read_table(s3_path, filesystem=s3fs)
    logger.info(
        "S3 Parquet read complete: %d rows, %d columns",
        table.num_rows,
        table.num_columns,
    )
    return table


def local_parquet_reader(path: str) -> pa.Table:
    """Read a local Parquet file via PyArrow.

    Args:
        path: Path to the Parquet file on disk.

    Returns:
        PyArrow Table with the Parquet data.
    """
    import pyarrow.parquet as pq

    logger.info("Reading local Parquet: %s", path)
    table = pq.read_table(path)
    logger.info(
        "Local Parquet read complete: %d rows, %d columns",
        table.num_rows,
        table.num_columns,
    )
    return table
