"""Iceberg gap-fill -> Ranger policy extractor.

Generates Ranger gap-fill masking and row-filter policies for Iceberg tables
on S3. These SUPPLEMENT (not replace) the Lake Formation + IAM governance
already present on the S3 data.

Gap-fill policies add fine-grained controls at the Trino layer that the
platform-native S3/LF governance cannot provide (column masking, row filtering).
The Iceberg data is still governed at Tier 1 by Lake Formation + IAM.

Labels: source:gap_fill, governance_tier:platform_native

SIMULATION NOTE: Policies are generated deterministically from the known schema
of ledger_entries_cold. In production, these would be derived from a policy
management system or data classification scan.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from dotenv import load_dotenv

from src.extractors.base import BaseExtractor

load_dotenv()

logger = logging.getLogger(__name__)

# Iceberg catalog name as registered in Gravitino / Trino
ICEBERG_CATALOG: str = os.getenv("ICEBERG_CATALOG", "iceberg_s3")
ICEBERG_SCHEMA: str = os.getenv("GLUE_DATABASE", "federation_demo")


class IcebergGapFillExtractor(BaseExtractor):
    """Generate Ranger gap-fill policies for Iceberg tables on S3.

    These policies add masking and row-filtering at the Trino layer.
    The underlying S3 data is already governed by Lake Formation + IAM
    (Tier 1), so these are supplemental controls.
    """

    def __init__(self) -> None:
        super().__init__(source_name="gap_fill")

    def extract_policies(self) -> list[dict[str, Any]]:
        """Generate gap-fill masking and row-filter policies for Iceberg cold tier."""
        policies: list[dict[str, Any]] = []

        policies.extend(self._pci_masking_policies())
        policies.extend(self._pii_masking_policies())
        policies.extend(self._row_filter_policies())
        policies.extend(self._access_policies())

        logger.info(
            "Generated %d Iceberg gap-fill policies for %s.%s",
            len(policies),
            ICEBERG_CATALOG,
            ICEBERG_SCHEMA,
        )
        return policies

    def _pci_masking_policies(self) -> list[dict[str, Any]]:
        """Gap-fill: mask token_id (PCI-DSS column) with SHOW_LAST_4."""
        return [
            self.make_masking_policy(
                name=f"iceberg_gap_fill_pci_token_id",
                database=ICEBERG_CATALOG,
                table="ledger_entries_cold",
                column="token_id",
                mask_type="MASK_SHOW_LAST_4",
                groups=["public"],
                extra_labels=[
                    "governance_tier:platform_native",
                    "gap_fill:pci_masking",
                    "platform_governance:lake_formation,iam",
                ],
                schema=ICEBERG_SCHEMA,
            )
        ]

    def _pii_masking_policies(self) -> list[dict[str, Any]]:
        """Gap-fill: hash entity_name and account_ref (PII columns)."""
        policies: list[dict[str, Any]] = []
        pii_columns = ["entity_name", "account_ref"]

        for col in pii_columns:
            policies.append(
                self.make_masking_policy(
                    name=f"iceberg_gap_fill_pii_{col}",
                    database=ICEBERG_CATALOG,
                    table="ledger_entries_cold",
                    column=col,
                    mask_type="MASK_HASH",
                    groups=["public"],
                    extra_labels=[
                        "governance_tier:platform_native",
                        "gap_fill:pii_masking",
                        "platform_governance:lake_formation,iam",
                    ],
                    schema=ICEBERG_SCHEMA,
                )
            )
        return policies

    def _row_filter_policies(self) -> list[dict[str, Any]]:
        """Gap-fill: row filter by jurisdiction for cold tier data."""
        return [
            self.make_row_filter_policy(
                name="iceberg_gap_fill_jurisdiction_filter",
                database=ICEBERG_CATALOG,
                table="ledger_entries_cold",
                filter_expr="jurisdiction = 'NA'",
                groups=["na_analysts"],
                extra_labels=[
                    "governance_tier:platform_native",
                    "gap_fill:row_filter",
                    "platform_governance:lake_formation,iam",
                ],
                schema=ICEBERG_SCHEMA,
            )
        ]

    def _access_policies(self) -> list[dict[str, Any]]:
        """Gap-fill: baseline access policy for Iceberg cold tier."""
        return [
            self.make_access_policy(
                name="iceberg_gap_fill_cold_tier_access",
                database=ICEBERG_CATALOG,
                table="ledger_entries_cold",
                groups=["federation_readers"],
                extra_labels=[
                    "governance_tier:platform_native",
                    "gap_fill:access",
                    "platform_governance:lake_formation,iam",
                ],
                schema=ICEBERG_SCHEMA,
            )
        ]


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = IcebergGapFillExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Iceberg gap-fill extractor result: %s", result)
