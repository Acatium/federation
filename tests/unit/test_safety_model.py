"""Pure unit tests for the safe-by-default safety model — no infrastructure.

These exercise `src/governance/safety_model.py` directly: the computed (not
hardcoded) safety analysis for every Ranger×platform sync-gap combination, the
staleness scenarios, the per-engine governance stacks, and the Arrow transport
governance table. They run offline with no DB, network, or cloud credentials —
the same property the rest of `tests/unit/` has.
"""

from __future__ import annotations

import pytest

from src.governance.safety_model import (
    ACCESS_PATTERNS,
    ARROW_TRANSPORTS,
    STALENESS_SCENARIOS,
    SYNC_GAP_QUADRANTS,
    EnforcementState,
    all_access_patterns,
    analyze_sync_gap,
    compute_governance_delta,
    get_access_pattern,
    get_engine_governance_stack,
)


class TestSyncGapSafety:
    """The core safe-by-default property: every state combination is safe."""

    def test_all_four_canonical_quadrants_are_safe(self) -> None:
        """For all four canonical quadrants, the computed outcome is safe."""
        assert set(SYNC_GAP_QUADRANTS) == {
            "over_permissive_ranger",
            "under_permissive_ranger",
            "sync_current_allow",
            "both_deny",
        }
        for name, (ranger, platform) in SYNC_GAP_QUADRANTS.items():
            outcome = analyze_sync_gap(ranger, platform)
            assert outcome.is_safe, f"quadrant {name} computed as UNSAFE"

    def test_every_possible_state_combination_is_safe(self) -> None:
        """Exhaustively: no Ranger×platform pair yields an unsafe outcome."""
        for ranger in EnforcementState:
            for platform in EnforcementState:
                outcome = analyze_sync_gap(ranger, platform)
                assert outcome.is_safe, f"unsafe: ranger={ranger}, platform={platform}"

    def test_access_requires_both_layers_to_allow(self) -> None:
        """Logical AND: access is granted only when both layers allow."""
        allow_states = (EnforcementState.ALLOW, EnforcementState.STALE_ALLOW)
        for ranger in EnforcementState:
            for platform in EnforcementState:
                outcome = analyze_sync_gap(ranger, platform)
                expected = ranger in allow_states and platform in allow_states
                assert outcome.access_granted is expected

    def test_over_permissive_ranger_is_blocked_by_platform(self) -> None:
        """Stale ALLOW in Ranger but platform DENY → blocked at source (no leak)."""
        outcome = analyze_sync_gap(EnforcementState.STALE_ALLOW, EnforcementState.DENY)
        assert outcome.access_granted is False
        assert outcome.is_safe is True
        assert outcome.outcome_type == "platform_backstop"

    def test_under_permissive_ranger_fails_closed(self) -> None:
        """Stale DENY in Ranger but platform ALLOW → user blocked at Ranger (fail-closed)."""
        outcome = analyze_sync_gap(EnforcementState.STALE_DENY, EnforcementState.ALLOW)
        assert outcome.access_granted is False
        assert outcome.is_safe is True
        assert outcome.outcome_type == "fail_closed"


class TestStalenessScenarios:
    """Catalog sync-drift scenarios are safe by construction."""

    def test_all_staleness_scenarios_are_safe(self) -> None:
        assert len(STALENESS_SCENARIOS) > 0
        for name, scenario in STALENESS_SCENARIOS.items():
            assert scenario.is_safe, f"staleness scenario {name} is not safe"
            assert scenario.outcome in ("fail-safe", "fail-closed")


class TestGovernanceStacks:
    """Per-engine governance stacks and the Trino vs. Spark delta."""

    def test_every_engine_has_at_least_two_controls(self) -> None:
        for engine in ("trino", "spark", "direct_access", "redshift", "snowflake"):
            stack = get_engine_governance_stack(engine)
            assert len(stack.controls) >= 2, f"{engine} has < 2 controls"

    def test_trino_adds_masking_and_row_filtering_over_spark(self) -> None:
        """The governed (Trino) path carries controls the direct (Spark) path lacks."""
        delta = compute_governance_delta("trino", "spark")
        assert delta.has_masking_gap is True
        assert delta.has_row_filter_gap is True

    def test_unknown_engine_raises(self) -> None:
        with pytest.raises(ValueError):
            get_engine_governance_stack("nonexistent-engine")


class TestAccessPatternsAndArrow:
    """The three access patterns and Arrow transport governance."""

    def test_three_access_patterns(self) -> None:
        assert [p.name for p in all_access_patterns()] == ["Discover", "Query", "Access"]
        assert set(ACCESS_PATTERNS) == {"discover", "query", "access"}

    def test_unknown_access_pattern_raises(self) -> None:
        with pytest.raises(ValueError):
            get_access_pattern("nope")

    def test_static_iam_arrow_is_the_only_ungoverned_transport(self) -> None:
        """Direct PyArrow→S3 with static IAM is the documented governance gap;
        every other Arrow transport is governed."""
        ungoverned = [t for t in ARROW_TRANSPORTS if not t.governed]
        assert len(ungoverned) == 1
        assert "static IAM" in ungoverned[0].transport_name
