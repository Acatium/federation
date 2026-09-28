"""Pure unit tests for the safety model — no infrastructure.

These exercise `src/governance/safety_model.py` directly: the sync-gap outcome
for every Ranger×platform combination under each identity mode, the staleness
scenarios, the per-engine governance stacks, and the Arrow transport governance
table. Every sync-gap test names the identity mode it covers; this repository
is deployed with shared service accounts (`IdentityMode.SERVICE_ACCOUNT`).
"""

from __future__ import annotations

import pytest

from src.governance.safety_model import (
    ACCESS_PATTERNS,
    ARROW_TRANSPORTS,
    STALENESS_SCENARIOS,
    SYNC_GAP_QUADRANTS,
    EnforcementState,
    IdentityMode,
    all_access_patterns,
    analyze_sync_gap,
    compute_governance_delta,
    get_access_pattern,
    get_engine_governance_stack,
)

AS_DEPLOYED = IdentityMode.SERVICE_ACCOUNT
PASSTHROUGH = IdentityMode.PASSTHROUGH


class TestSyncGapWithPassthrough:
    """With identity passthrough, every state combination is safe."""

    def test_all_four_canonical_quadrants_are_safe(self) -> None:
        assert set(SYNC_GAP_QUADRANTS) == {
            "over_permissive_ranger",
            "under_permissive_ranger",
            "sync_current_allow",
            "both_deny",
        }
        for name, (ranger, platform) in SYNC_GAP_QUADRANTS.items():
            outcome = analyze_sync_gap(ranger, platform, PASSTHROUGH)
            assert outcome.is_safe, f"quadrant {name} computed as UNSAFE"

    def test_every_possible_state_combination_is_safe(self) -> None:
        for ranger in EnforcementState:
            for platform in EnforcementState:
                outcome = analyze_sync_gap(ranger, platform, PASSTHROUGH)
                assert outcome.is_safe, f"unsafe: ranger={ranger}, platform={platform}"

    def test_access_requires_both_layers_to_allow(self) -> None:
        allow_states = (EnforcementState.ALLOW, EnforcementState.STALE_ALLOW)
        for ranger in EnforcementState:
            for platform in EnforcementState:
                outcome = analyze_sync_gap(ranger, platform, PASSTHROUGH)
                expected = ranger in allow_states and platform in allow_states
                assert outcome.access_granted is expected

    def test_over_permissive_ranger_is_blocked_by_platform(self) -> None:
        outcome = analyze_sync_gap(EnforcementState.STALE_ALLOW, EnforcementState.DENY, PASSTHROUGH)
        assert outcome.access_granted is False
        assert outcome.outcome_type == "platform_backstop"


class TestSyncGapAsDeployed:
    """With the shared service accounts this repository deploys, one quadrant leaks."""

    def test_over_permissive_ranger_leaks(self) -> None:
        outcome = analyze_sync_gap(EnforcementState.STALE_ALLOW, EnforcementState.DENY, AS_DEPLOYED)
        assert outcome.access_granted is True
        assert outcome.is_safe is False

    def test_only_the_over_permissive_quadrant_is_unsafe(self) -> None:
        unsafe = {
            name
            for name, (ranger, platform) in SYNC_GAP_QUADRANTS.items()
            if not analyze_sync_gap(ranger, platform, AS_DEPLOYED).is_safe
        }
        assert unsafe == {"over_permissive_ranger"}

    @pytest.mark.parametrize("mode", list(IdentityMode))
    def test_under_permissive_ranger_fails_closed_in_every_mode(self, mode: IdentityMode) -> None:
        outcome = analyze_sync_gap(EnforcementState.STALE_DENY, EnforcementState.ALLOW, mode)
        assert outcome.access_granted is False
        assert outcome.outcome_type == "fail_closed"


class TestStalenessScenarios:
    def test_all_staleness_scenarios_are_safe_with_passthrough(self) -> None:
        assert len(STALENESS_SCENARIOS) > 0
        for name, scenario in STALENESS_SCENARIOS.items():
            assert scenario.is_safe_under(PASSTHROUGH), f"staleness scenario {name} is not safe"
            assert scenario.outcome_under(PASSTHROUGH) in ("fail-safe", "fail-closed")

    def test_as_deployed_only_the_stale_allow_scenario_is_unsafe(self) -> None:
        unsafe = {n for n, sc in STALENESS_SCENARIOS.items() if not sc.is_safe_under(AS_DEPLOYED)}
        assert unsafe == {"stale_allow_ranger"}


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
