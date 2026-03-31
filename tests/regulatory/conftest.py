"""Regulatory test fixtures and marker registration."""

from __future__ import annotations

import logging
import os
from typing import Any

import polars as pl
import pytest

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Marker registration
# ---------------------------------------------------------------------------


def pytest_configure(config: Any) -> None:
    """Register the regulatory marker."""
    config.addinivalue_line(
        "markers",
        "regulatory: Regulatory compliance verification tests "
        "(BCBS239, DORA, GDPR, EU AI Act, SOX, SR11-7)",
    )


# ---------------------------------------------------------------------------
# Regulatory-specific fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def entitlement_matrix_df(ranger_policies: list[dict[str, Any]]) -> pl.DataFrame:
    """Build an EntitlementMatrix Polars DataFrame from ranger_policies.

    Falls back to an empty DataFrame if no policies are available.
    """
    from src.reports.entitlement_matrix import EntitlementMatrix

    matrix = EntitlementMatrix()
    try:
        df = matrix.build(policies=ranger_policies)
    except Exception as exc:
        logger.warning("Could not build entitlement matrix: %s", exc)
        from src.reports.entitlement_matrix import MATRIX_COLUMNS

        df = pl.DataFrame({col: pl.Series([], dtype=pl.Utf8) for col in MATRIX_COLUMNS})
    return df


@pytest.fixture(scope="session")
def regulatory_trino_cursor(trino_conn: Any) -> Any:
    """Return a cursor from trino_conn, skipping if unavailable."""
    if trino_conn is None:
        pytest.skip("Trino connection not available")
    return trino_conn.cursor()


@pytest.fixture(autouse=True)
def _reset_redshift_transaction(request: pytest.FixtureRequest) -> None:
    """Reset Redshift connection if it's in a failed transaction state.

    psycopg2 connections enter an error state after a failed query. Since
    redshift_conn is session-scoped, this cascades across tests. Rolling
    back before each test that might use Redshift prevents cascading failures.
    """
    redshift_conn = request.getfixturevalue("redshift_conn") if "redshift_conn" in request.fixturenames else None
    if redshift_conn is not None:
        try:
            redshift_conn.rollback()
        except Exception:
            pass


@pytest.fixture(scope="session")
def ranger_audit_url() -> str:
    """Return Solr audit URL from env vars, skipping if RANGER_HOST not set."""
    host = os.getenv("RANGER_HOST", "")
    if not host:
        pytest.skip("RANGER_HOST not configured — cannot query audit logs")
    port = os.getenv("RANGER_SOLR_PORT", "6083")
    scheme = os.getenv("RANGER_SCHEME", "http")
    return f"{scheme}://{host}:{port}/solr/ranger_audits/select"
