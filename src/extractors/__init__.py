"""Policy extractors: platform-native -> Ranger canonical format.

Each extractor connects to a source platform, reads native access control
policies, normalises them into Ranger's canonical policy schema with provenance
labels, and pushes them to Ranger via its REST API.

All extractors are idempotent — running twice produces the same Ranger state.
All sources are synced together through FederatedSync, which combines sources
that govern the same resource by AND (see src/sync/federated.py).
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
    """Extract every source, combine them by AND, and push the result once.

    Sources can govern the same resource: Lake Formation and Glue/IAM both write
    the hive catalog, and an Immuta policy sits over a platform's own grants.
    Pushed one after another, the last writer would win each shared resource,
    whatever the priority order. ``FederatedSync`` combines shared resources
    into the intersection of what every source allows and pushes one policy
    set. If any source fails to extract, nothing is pushed.

    Returns:
        Dict mapping "federated_sync" to the sync summary.
    """
    from src.sync.federated import FederatedSync

    logger.info("Starting federated policy sync across all extractors")
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
    sync = FederatedSync({e.source_name: e.extract_policies for e in extractors})
    summary = sync.extract_and_push()
    BaseExtractor.write_contract([summary])
    logger.info("Federated sync complete (%s). Contract written.", summary.get("status"))
    return {summary["source"]: summary}
