"""Column definitions and schema constants for federated governance demo tables.

All column names use sanitized identifiers — no production-looking PCI/PII column names.
See CLAUDE.md for the sanitization mapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from src.utils.sql_safety import validate_identifier

# ---------------------------------------------------------------------------
# Jurisdiction values (replaces 'region' EMEA/NA/APAC)
# ---------------------------------------------------------------------------
JURISDICTIONS: list[str] = ["NA", "EMEA", "APAC"]

# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------
ENTITY_TYPES: list[str] = ["individual", "corporate"]

# ---------------------------------------------------------------------------
# Signal types for risk_signals
# ---------------------------------------------------------------------------
SIGNAL_TYPES: list[str] = [
    "velocity_anomaly",
    "geo_mismatch",
    "amount_outlier",
    "device_fingerprint",
    "behavioral_drift",
]

# ---------------------------------------------------------------------------
# Categories for ledger entries and counterparties
# ---------------------------------------------------------------------------
ENTRY_CATEGORIES: list[str] = [
    "retail",
    "wholesale",
    "interbank",
    "treasury",
    "advisory",
]

COUNTERPARTY_STATUSES: list[str] = ["active", "inactive"]

COUNTERPARTY_CATEGORIES: list[str] = [
    "bank",
    "broker-dealer",
    "asset-manager",
    "insurance",
    "fintech",
    "corporate",
]


# ---------------------------------------------------------------------------
# Schema definitions (column name, SQL type) for each table
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ColumnDef:
    """One column in a table schema."""

    name: str
    sql_type: str
    pii: bool = False
    description: str = ""


# -- ledger_entries (hot = Redshift internal, warm = S3/Spectrum Parquet) ----
LEDGER_ENTRIES_COLUMNS: Sequence[ColumnDef] = (
    ColumnDef("entry_id", "BIGINT", description="Primary key"),
    ColumnDef("token_id", "VARCHAR(64)", pii=True, description="Tokenised payment identifier"),
    ColumnDef("account_ref", "VARCHAR(32)", pii=True, description="Generic account reference"),
    ColumnDef("entity_name", "VARCHAR(128)", pii=True, description="Person or organisation"),
    ColumnDef("amount", "DECIMAL(18,2)", description="Transaction amount"),
    ColumnDef("jurisdiction", "VARCHAR(8)", description="NA / EMEA / APAC"),
    ColumnDef("counterparty_id", "INTEGER", description="FK to counterparty_ref"),
    ColumnDef("entry_date", "DATE", description="When the entry was recorded"),
    ColumnDef("category", "VARCHAR(32)", description="Business category"),
)

# -- entities (Snowflake) ---------------------------------------------------
ENTITIES_COLUMNS: Sequence[ColumnDef] = (
    ColumnDef("entity_id", "INTEGER", description="Primary key"),
    ColumnDef("entity_name", "VARCHAR(128)", pii=True, description="Person or organisation"),
    ColumnDef("account_ref", "VARCHAR(32)", pii=True, description="Generic account reference"),
    ColumnDef("jurisdiction", "VARCHAR(8)", description="NA / EMEA / APAC"),
    ColumnDef("entity_type", "VARCHAR(16)", description="individual or corporate"),
    ColumnDef("created_date", "DATE", description="When the entity was on-boarded"),
)

# -- risk_signals (Databricks / local CSV fallback) -------------------------
RISK_SIGNALS_COLUMNS: Sequence[ColumnDef] = (
    ColumnDef("signal_id", "BIGINT", description="Primary key"),
    ColumnDef("entry_id", "BIGINT", description="FK to ledger_entries"),
    ColumnDef("risk_score", "DOUBLE", description="0.0 – 1.0 risk score"),
    ColumnDef("signal_type", "VARCHAR(32)", description="Type of risk signal"),
    ColumnDef("detected_date", "DATE", description="When the signal was detected"),
)

# -- counterparty_ref (S3 Parquet / Spectrum) --------------------------------
COUNTERPARTY_REF_COLUMNS: Sequence[ColumnDef] = (
    ColumnDef("counterparty_id", "INTEGER", description="Primary key"),
    ColumnDef("counterparty_name", "VARCHAR(128)", description="Counterparty display name"),
    ColumnDef("jurisdiction", "VARCHAR(8)", description="NA / EMEA / APAC"),
    ColumnDef("category", "VARCHAR(32)", description="Business category"),
    ColumnDef("status", "VARCHAR(16)", description="active / inactive"),
)


# ---------------------------------------------------------------------------
# Redshift DDL helpers
# ---------------------------------------------------------------------------

def redshift_create_table_ddl(
    schema: str,
    table: str,
    columns: Sequence[ColumnDef],
    *,
    diststyle: str = "KEY",
    distkey: str | None = None,
    sortkey: str | None = None,
) -> str:
    """Return a Redshift CREATE TABLE statement."""
    validate_identifier(schema)
    validate_identifier(table)
    col_lines = []
    for c in columns:
        col_lines.append(f"    {c.name} {c.sql_type}")
    body = ",\n".join(col_lines)
    ddl = f"CREATE TABLE IF NOT EXISTS {schema}.{table} (\n{body}\n)"
    clauses: list[str] = []
    if diststyle:
        clauses.append(f"DISTSTYLE {diststyle}")
    if distkey:
        clauses.append(f"DISTKEY({distkey})")
    if sortkey:
        clauses.append(f"SORTKEY({sortkey})")
    if clauses:
        ddl += "\n" + "\n".join(clauses)
    return ddl + ";"


def snowflake_create_table_ddl(
    database: str,
    schema: str,
    table: str,
    columns: Sequence[ColumnDef],
) -> str:
    """Return a Snowflake CREATE TABLE statement."""
    validate_identifier(database)
    validate_identifier(schema)
    validate_identifier(table)
    type_map = {
        "BIGINT": "NUMBER(19,0)",
        "INTEGER": "NUMBER(10,0)",
        "DOUBLE": "FLOAT",
        "DECIMAL(18,2)": "NUMBER(18,2)",
    }
    col_lines = []
    for c in columns:
        sf_type = type_map.get(c.sql_type, c.sql_type)
        col_lines.append(f"    {c.name} {sf_type}")
    body = ",\n".join(col_lines)
    return (
        f"CREATE TABLE IF NOT EXISTS {database}.{schema}.{table} (\n{body}\n);"
    )


def glue_columns(columns: Sequence[ColumnDef]) -> list[dict[str, str]]:
    """Return a list of dicts suitable for boto3 Glue create_table Columns param."""
    type_map = {
        "BIGINT": "bigint",
        # Polars stores all ints as int64 in Parquet, so Glue must use bigint
        "INTEGER": "bigint",
        "DOUBLE": "double",
        # Polars writes amount as float64/double in Parquet, so Glue must match
        "DECIMAL(18,2)": "double",
        "DATE": "date",
    }
    result = []
    for c in columns:
        glue_type = type_map.get(c.sql_type, "string")
        result.append({"Name": c.name, "Type": glue_type})
    return result
