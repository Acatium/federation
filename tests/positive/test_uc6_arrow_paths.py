"""UC-5/UC-6: Arrow Query Paths.

Verifies that S3 Parquet data can be read directly via PyArrow, and
compares the row count with the governed Spectrum path. The governance
gap (direct S3 reads bypass Ranger) is documented as a known finding.
"""
import logging
import os
from typing import Any

import pytest
import pyarrow as pa
import pyarrow.parquet as pq
from pyarrow.fs import S3FileSystem

logger = logging.getLogger(__name__)


class TestArrowQueryPaths:
    """Verify direct S3 Parquet access via PyArrow and compare with Spectrum."""

    @pytest.mark.slow
    def test_s3_parquet_direct_read(
        self, s3_bucket: str, aws_region: str
    ) -> None:
        """Read the ledger_entries_warm Parquet from S3 via PyArrow.

        This path bypasses all governance layers (Ranger, Redshift RBAC,
        Lake Formation). Anyone with S3 credentials can read the raw data.
        """
        s3fs = S3FileSystem(region=aws_region)
        s3_path = f"{s3_bucket}/spectrum/ledger_entries_warm/data.parquet"

        logger.info("Reading Parquet from s3://%s", s3_path)
        table = pq.read_table(s3_path, filesystem=s3fs)

        assert isinstance(table, pa.Table), "Expected a PyArrow Table"
        assert table.num_rows > 0, "S3 Parquet read returned 0 rows"
        logger.info(
            "S3 direct read: %d rows, %d columns, schema: %s",
            table.num_rows,
            table.num_columns,
            table.schema,
        )

        # SIMULATION NOTE: This direct read bypasses Ranger entirely.
        # In production, S3 bucket policies and IAM would be the only
        # access control. Ranger does NOT govern this path.

        # Verify expected row count (~500K per data contract)
        assert table.num_rows >= 400_000, (
            f"Expected ~500K rows, got {table.num_rows}"
        )

    @pytest.mark.slow
    def test_arrow_row_count_matches_spectrum(
        self,
        redshift_conn: Any,
        s3_bucket: str,
        aws_region: str,
    ) -> None:
        """Compare row counts: direct S3 Parquet vs Spectrum external table.

        Both paths read the same underlying data. Row counts should match,
        proving that the data is identical regardless of governance path.
        """
        # Path A: Direct S3 via PyArrow (ungoverned)
        s3fs = S3FileSystem(region=aws_region)
        s3_path = f"{s3_bucket}/spectrum/ledger_entries_warm/data.parquet"
        arrow_table = pq.read_table(s3_path, filesystem=s3fs)
        arrow_count = arrow_table.num_rows

        # Path B: Spectrum (governed by Redshift RBAC + Lake Formation)
        cur = redshift_conn.cursor()
        try:
            cur.execute(
                "SELECT count(*) FROM spectrum_federation.ledger_entries_warm"
            )
            spectrum_count = cur.fetchone()[0]
        finally:
            cur.close()

        logger.info(
            "Row count comparison: Arrow(S3)=%d, Spectrum=%d",
            arrow_count,
            spectrum_count,
        )

        assert arrow_count == spectrum_count, (
            f"Row count mismatch: Arrow(S3)={arrow_count}, "
            f"Spectrum={spectrum_count}. Same data should produce same count."
        )

        # SIMULATION NOTE: Both paths return the same data, but only the
        # Spectrum path is governed. The Arrow/S3 path bypasses Ranger,
        # Redshift RBAC, and Lake Formation entirely.

    @pytest.mark.slow
    def test_arrow_schema_matches_spectrum(
        self,
        redshift_conn: Any,
        s3_bucket: str,
        aws_region: str,
    ) -> None:
        """Verify that Arrow and Spectrum expose the same columns.

        Column names should match (modulo type differences) since they
        read the same Parquet files.
        """
        # Arrow schema
        s3fs = S3FileSystem(region=aws_region)
        s3_path = f"{s3_bucket}/spectrum/ledger_entries_warm/data.parquet"
        arrow_table = pq.read_table(s3_path, filesystem=s3fs)
        arrow_columns = set(arrow_table.schema.names)

        # Spectrum schema
        cur = redshift_conn.cursor()
        try:
            cur.execute(
                "SELECT * FROM spectrum_federation.ledger_entries_warm LIMIT 1"
            )
            spectrum_columns = set(d.name for d in cur.description)
        finally:
            cur.close()

        logger.info("Arrow columns: %s", sorted(arrow_columns))
        logger.info("Spectrum columns: %s", sorted(spectrum_columns))

        # Columns should match
        assert arrow_columns == spectrum_columns, (
            f"Column mismatch. Arrow-only: {arrow_columns - spectrum_columns}, "
            f"Spectrum-only: {spectrum_columns - arrow_columns}"
        )

    @pytest.mark.slow
    def test_governance_gap_documented(
        self, s3_bucket: str, aws_region: str
    ) -> None:
        """Document and verify the governance gap for direct S3 access.

        Direct S3 Parquet reads bypass ALL governance layers:
        - No Ranger enforcement
        - No Redshift RBAC
        - No Lake Formation (PyArrow uses IAM credentials, not LF grants)
        - No Immuta masking

        The only access control is the S3 bucket policy and IAM credentials.
        This is the expected risk documented in NEG-8.
        """
        # SIMULATION NOTE: This test documents the governance gap.
        # In production, the mitigation would be:
        # 1. S3 bucket policies restrict access to approved IAM roles
        # 2. Lake Formation restricts Glue catalog access
        # 3. VPC endpoints limit network-level access to S3
        # But NONE of these are Ranger-enforced.

        s3fs = S3FileSystem(region=aws_region)
        s3_path = f"{s3_bucket}/spectrum/ledger_entries_warm/data.parquet"
        table = pq.read_table(s3_path, filesystem=s3fs)

        # Prove we can access PII columns directly (no masking)
        pii_columns = {"token_id", "account_ref", "entity_name"}
        table_columns = set(table.schema.names)
        accessible_pii = pii_columns & table_columns

        logger.info(
            "GOVERNANCE GAP: PII columns accessible via direct S3 read "
            "without any masking: %s",
            accessible_pii,
        )
        assert len(accessible_pii) > 0, (
            "Expected at least one PII column accessible via direct S3 read"
        )

        # Verify the PII data is unmasked (raw values)
        if "token_id" in table_columns:
            sample = table.column("token_id").to_pylist()[:5]
            logger.info(
                "GOVERNANCE GAP: Raw token_id values from S3: %s "
                "(no Ranger masking applied)",
                sample,
            )
            assert any(v is not None for v in sample), (
                "Expected at least one non-null raw PII value in direct S3 read"
            )
