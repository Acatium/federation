"""Unit tests for sync configuration."""

from __future__ import annotations

import logging

import pytest

from src.sync.config import SyncConfig, DEFAULT_SOURCE_PRIORITY

logger = logging.getLogger(__name__)


class TestSyncConfigDefaults:
    """Tests for default SyncConfig values."""

    def test_default_tier2_interval(self) -> None:
        """SyncConfig default tier2 interval is 900 seconds (15 min)."""
        config = SyncConfig()
        assert config.tier2_interval_seconds == 900
        logger.info("Tier 2 (FGAC) sync interval: %ds", config.tier2_interval_seconds)

    def test_default_tier1_interval(self) -> None:
        """SyncConfig default tier1 interval is 3600 seconds (1 hr)."""
        config = SyncConfig()
        assert config.tier1_interval_seconds == 3600
        logger.info("Tier 1 (platform-native) sync interval: %ds", config.tier1_interval_seconds)

    def test_default_stale_grace_period(self) -> None:
        """SyncConfig default stale grace period is 7200 seconds (2 hr)."""
        config = SyncConfig()
        assert config.stale_grace_period_seconds == 7200
        logger.info("Stale grace period: %ds", config.stale_grace_period_seconds)

    def test_default_interval(self) -> None:
        """SyncConfig default sync interval is 86400 seconds (24 hr)."""
        config = SyncConfig()
        assert config.default_interval_seconds == 86400
        logger.info("Default sync interval: %ds", config.default_interval_seconds)

    def test_default_priority_map(self) -> None:
        """SyncConfig defaults include all expected sources."""
        config = SyncConfig()
        assert config.source_priority == DEFAULT_SOURCE_PRIORITY
        assert "immuta" in config.source_priority
        assert "lake_formation" in config.source_priority
        logger.info("Source priority map: %s", config.source_priority)


class TestSyncConfigFromEnv:
    """Tests for SyncConfig.from_env()."""

    def test_from_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables override default values."""
        monkeypatch.setenv("SYNC_TIER2_INTERVAL", "300")
        monkeypatch.setenv("SYNC_TIER1_INTERVAL", "1800")
        monkeypatch.setenv("SYNC_DEFAULT_INTERVAL", "43200")
        monkeypatch.setenv("SYNC_STALE_GRACE_PERIOD", "3600")

        config = SyncConfig.from_env()
        assert config.tier2_interval_seconds == 300
        assert config.tier1_interval_seconds == 1800
        assert config.default_interval_seconds == 43200
        assert config.stale_grace_period_seconds == 3600
        logger.info(
            "Env overrides applied: tier2=%ds, tier1=%ds, default=%ds, grace=%ds",
            config.tier2_interval_seconds, config.tier1_interval_seconds,
            config.default_interval_seconds, config.stale_grace_period_seconds,
        )

    def test_from_env_defaults_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When env vars are not set, defaults are used."""
        monkeypatch.delenv("SYNC_TIER2_INTERVAL", raising=False)
        monkeypatch.delenv("SYNC_TIER1_INTERVAL", raising=False)
        config = SyncConfig.from_env()
        assert config.tier2_interval_seconds == 900
        assert config.tier1_interval_seconds == 3600
        logger.info(
            "Env unset, defaults used: tier2=%ds, tier1=%ds",
            config.tier2_interval_seconds, config.tier1_interval_seconds,
        )


class TestSyncConfigConflictResolution:
    """Tests for resolve_conflict() and get_priority()."""

    def test_resolve_conflict_higher_wins(self) -> None:
        """Higher-priority source wins conflict resolution."""
        config = SyncConfig()
        winner1 = config.resolve_conflict("immuta", "redshift")
        winner2 = config.resolve_conflict("redshift", "immuta")
        assert winner1 == "immuta"
        assert winner2 == "immuta"
        logger.info("Conflict immuta vs redshift: winner=%s (immuta priority=%d, redshift=%d)",
                     winner1, config.get_priority("immuta"), config.get_priority("redshift"))

    def test_resolve_conflict_equal_priority(self) -> None:
        """When priorities are equal, first argument wins (stable)."""
        config = SyncConfig()
        assert config.resolve_conflict("redshift", "snowflake") == "redshift"
        assert config.resolve_conflict("snowflake", "redshift") == "snowflake"
        logger.info("Equal priority: first arg wins (stable). redshift=%d, snowflake=%d",
                     config.get_priority("redshift"), config.get_priority("snowflake"))

    def test_get_priority_known_source(self) -> None:
        """Known sources return their configured priority."""
        config = SyncConfig()
        assert config.get_priority("immuta") == 100
        assert config.get_priority("lake_formation") == 80
        assert config.get_priority("bedrock") == 20
        logger.info("Priorities: immuta=%d, lake_formation=%d, bedrock=%d",
                     config.get_priority("immuta"), config.get_priority("lake_formation"),
                     config.get_priority("bedrock"))

    def test_get_priority_unknown_source(self) -> None:
        """Unknown source returns 0 (lowest priority)."""
        config = SyncConfig()
        p = config.get_priority("nonexistent_source")
        assert p == 0
        logger.info("Unknown source 'nonexistent_source' priority: %d", p)

    def test_get_interval_immuta(self) -> None:
        """Immuta uses tier2 interval."""
        config = SyncConfig()
        interval = config.get_interval("immuta")
        assert interval == 900
        logger.info("Immuta sync interval: %ds (tier 2)", interval)

    def test_get_interval_lake_formation(self) -> None:
        """Lake Formation uses tier1 interval."""
        config = SyncConfig()
        interval = config.get_interval("lake_formation")
        assert interval == 3600
        logger.info("Lake Formation sync interval: %ds (tier 1)", interval)

    def test_get_interval_bedrock(self) -> None:
        """Low-priority sources use default interval."""
        config = SyncConfig()
        interval = config.get_interval("bedrock")
        assert interval == 86400
        logger.info("Bedrock sync interval: %ds (default tier)", interval)

    def test_to_dict(self) -> None:
        """to_dict returns a serializable dict with all fields."""
        config = SyncConfig()
        d = config.to_dict()
        assert "tier2_interval_seconds" in d
        assert "source_priority" in d
        assert isinstance(d["source_priority"], dict)
        logger.info("SyncConfig.to_dict() keys: %s", sorted(d.keys()))
