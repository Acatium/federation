"""Sync configuration for federated policy extraction.

Defines sync intervals per governance tier, source priority ordering for
conflict resolution, and stale grace periods. All values are overridable
via environment variables.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default priority ordering for policy sources.
# Higher value = higher priority in conflict resolution.
DEFAULT_SOURCE_PRIORITY: dict[str, int] = {
    "immuta": 100,
    "lake_formation": 80,
    "redshift": 60,
    "snowflake": 60,
    "unity_catalog": 50,
    "glue_iam": 40,
    "gap_fill": 30,
    "bedrock": 20,
}


@dataclass
class SyncConfig:
    """Configuration for policy sync intervals and conflict resolution.

    Attributes:
        tier2_interval_seconds: Sync interval for Tier 2 (Immuta FGAC) sources.
        tier1_interval_seconds: Sync interval for Tier 1 (platform-native) sources.
        default_interval_seconds: Sync interval for reference/supplementary sources.
        stale_grace_period_seconds: Time after which unseen policies are flagged stale.
        source_priority: Priority ordering for conflict resolution (higher wins).
    """

    tier2_interval_seconds: int = 900
    tier1_interval_seconds: int = 3600
    default_interval_seconds: int = 86400
    stale_grace_period_seconds: int = 7200
    source_priority: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_SOURCE_PRIORITY))

    @classmethod
    def from_env(cls) -> SyncConfig:
        """Create a SyncConfig from environment variables.

        Reads SYNC_TIER1_INTERVAL, SYNC_TIER2_INTERVAL, SYNC_DEFAULT_INTERVAL,
        and SYNC_STALE_GRACE_PERIOD from the environment. Falls back to defaults
        if not set.
        """
        return cls(
            tier2_interval_seconds=int(os.getenv("SYNC_TIER2_INTERVAL", "900")),
            tier1_interval_seconds=int(os.getenv("SYNC_TIER1_INTERVAL", "3600")),
            default_interval_seconds=int(os.getenv("SYNC_DEFAULT_INTERVAL", "86400")),
            stale_grace_period_seconds=int(os.getenv("SYNC_STALE_GRACE_PERIOD", "7200")),
        )

    def get_priority(self, source_name: str) -> int:
        """Return the priority for a given source name.

        Unknown sources return 0 (lowest priority).

        Args:
            source_name: The extractor source name.

        Returns:
            Integer priority (higher = wins conflicts).
        """
        return self.source_priority.get(source_name, 0)

    def resolve_conflict(self, source_a: str, source_b: str) -> str:
        """Return the higher-priority source name.

        When priorities are equal, the first argument wins (stable ordering).

        Args:
            source_a: First source name.
            source_b: Second source name.

        Returns:
            The source name with higher (or equal) priority.
        """
        if self.get_priority(source_a) >= self.get_priority(source_b):
            return source_a
        return source_b

    def get_interval(self, source_name: str) -> int:
        """Return the sync interval in seconds for a given source.

        Args:
            source_name: The extractor source name.

        Returns:
            Sync interval in seconds.
        """
        if source_name == "immuta":
            return self.tier2_interval_seconds
        priority = self.get_priority(source_name)
        if priority >= 40:
            return self.tier1_interval_seconds
        return self.default_interval_seconds

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to a dict for logging/contracts."""
        return {
            "tier2_interval_seconds": self.tier2_interval_seconds,
            "tier1_interval_seconds": self.tier1_interval_seconds,
            "default_interval_seconds": self.default_interval_seconds,
            "stale_grace_period_seconds": self.stale_grace_period_seconds,
            "source_priority": dict(self.source_priority),
        }
