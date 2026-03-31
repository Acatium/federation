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

    Returns dict with catalog -> schemas -> tables -> columns structure,
    suitable for feeding to an LLM as context.
    """
    metadata: dict[str, Any] = {"catalogs": {}}
    for catalog_name in gravitino_catalogs:
        cat_meta: dict[str, Any] = {"schemas": {}}
        try:
            # Get catalog details
            resp = requests.get(
                f"{gravitino_base_url}/api/metalakes/federation/catalogs/{catalog_name}",
                timeout=30,
            )
            if resp.ok:
                cat_data = resp.json()
                cat_obj = cat_data.get("catalog", cat_data)
                cat_meta["properties"] = cat_obj.get("properties", {})
                cat_meta["type"] = cat_obj.get("type", "RELATIONAL")

            # Get schemas
            resp = requests.get(
                f"{gravitino_base_url}/api/metalakes/federation/catalogs/{catalog_name}/schemas",
                timeout=30,
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
                            timeout=30,
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
