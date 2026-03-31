"""Policy extractors: platform-native -> Ranger canonical format.

Each extractor connects to a source platform, reads native access control
policies, normalises them into Ranger's canonical policy schema with provenance
labels, and pushes them to Ranger via its REST API.

All extractors are idempotent — running twice produces the same Ranger state.
Extraction order is determined by source priority (highest first) from SyncConfig.
"""

from __future__ import annotations

import logging
from typing import Any

from src.extractors.base import BaseExtractor
from src.extractors.lf_to_ranger import LakeFormationExtractor
from src.extractors.glue_iam_to_ranger import GlueIamExtractor
from src.extractors.redshift_to_ranger import RedshiftExtractor
from src.extractors.snowflake_to_ranger import SnowflakeExtractor
from src.extractors.uc_to_ranger import UnityCatalogExtractor
from src.extractors.immuta_to_ranger import ImmutaExtractor
from src.extractors.iceberg_gap_fill import IcebergGapFillExtractor
from src.extractors.bedrock_to_ranger import BedrockExtractor
from src.sync.config import SyncConfig

logger = logging.getLogger(__name__)

__all__ = [
    "BaseExtractor",
    "LakeFormationExtractor",
    "GlueIamExtractor",
    "RedshiftExtractor",
    "SnowflakeExtractor",
    "UnityCatalogExtractor",
    "ImmutaExtractor",
    "IcebergGapFillExtractor",
    "BedrockExtractor",
    "run_all_extractors",
]


def run_all_extractors() -> dict[str, dict[str, Any]]:
    """Run all extractors ordered by priority and write the consolidated contract.

    Extractors are ordered by descending source priority from SyncConfig,
    so that higher-priority sources (e.g., Immuta) run first and their
    policies take precedence in Ranger when resources overlap.

    Returns:
        Dict mapping source_name to extraction summary.
    """
    config = SyncConfig.from_env()
    logger.info("Starting all policy extractors (priority-ordered)")

    extractors: list[BaseExtractor] = [
        ImmutaExtractor(),
        LakeFormationExtractor(),
        GlueIamExtractor(),
        RedshiftExtractor(),
        SnowflakeExtractor(),
        UnityCatalogExtractor(),
        IcebergGapFillExtractor(),
        BedrockExtractor(),
    ]

    # Sort by descending priority
    extractors.sort(
        key=lambda e: config.get_priority(e.source_name),
        reverse=True,
    )

    summaries: list[dict[str, Any]] = []
    for extractor in extractors:
        try:
            summary = extractor.extract_and_push()
            summaries.append(summary)
        except Exception as exc:
            logger.error(
                "Extractor %s failed fatally: %s",
                extractor.source_name,
                exc,
            )
            summaries.append(
                {
                    "source": extractor.source_name,
                    "status": "error",
                    "error": str(exc),
                    "policies_extracted": 0,
                    "policies_pushed": 0,
                }
            )

    BaseExtractor.write_contract(summaries)
    logger.info("All extractors complete. Contract written.")
    return {s["source"]: s for s in summaries}
