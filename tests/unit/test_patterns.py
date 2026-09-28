"""Comparing governance patterns on one revocation: how long does the person keep access?"""

from __future__ import annotations

import math

import pytest

from src.governance.patterns import (
    COVERAGE,
    Pattern,
    RevocationScope,
    Scenario,
    Timings,
    coverage_table,
    exposure_after_revocation,
    exposure_table,
)
from src.governance.safety_model import IdentityMode

T = Timings(batch_sync=900, event_sync=30, push=60, credential_ttl=3600, decision_cache=60)


def exposure(pattern: Pattern, identity: IdentityMode, **kw: object):  # type: ignore[no-untyped-def]
    return exposure_after_revocation(Scenario(pattern, identity, **kw), T)  # type: ignore[arg-type]


class TestMirror:
    def test_passthrough_closes_at_the_platform_immediately(self) -> None:
        result = exposure(Pattern.MIRROR, IdentityMode.PASSTHROUGH)
        assert result.worst_seconds == 0
        assert result.closed_by.startswith("platform")

    def test_shared_account_waits_for_the_next_sync(self) -> None:
        result = exposure(Pattern.MIRROR, IdentityMode.SERVICE_ACCOUNT)
        assert result.worst_seconds == T.batch_sync
        assert result.expected_seconds == T.batch_sync / 2

    def test_event_driven_sync_shrinks_the_window(self) -> None:
        batch = exposure(Pattern.MIRROR, IdentityMode.SERVICE_ACCOUNT)
        event = exposure(Pattern.MIRROR, IdentityMode.SERVICE_ACCOUNT, event_driven=True)
        assert event.worst_seconds == T.event_sync < batch.worst_seconds

    def test_per_group_accounts_catch_group_revocations_but_not_one_person(self) -> None:
        group = exposure(Pattern.MIRROR, IdentityMode.PER_GROUP_ACCOUNT, scope=RevocationScope.GROUP)
        person = exposure(Pattern.MIRROR, IdentityMode.PER_GROUP_ACCOUNT, scope=RevocationScope.PERSON)
        assert group.worst_seconds == 0
        assert person.worst_seconds == T.batch_sync


class TestPatternsThatEnforceBelowTheEngine:
    @pytest.mark.parametrize("pattern", [Pattern.PUSH_DOWN, Pattern.CATALOG_AUTHORITY])
    def test_a_shared_account_never_closes_one_persons_revocation(self, pattern: Pattern) -> None:
        assert exposure(pattern, IdentityMode.SERVICE_ACCOUNT).never_closes

    def test_push_down_closes_once_pushed_with_passthrough(self) -> None:
        assert exposure(Pattern.PUSH_DOWN, IdentityMode.PASSTHROUGH).worst_seconds == T.push

    def test_catalog_authority_is_bounded_by_vended_credential_lifetime(self) -> None:
        result = exposure(Pattern.CATALOG_AUTHORITY, IdentityMode.PASSTHROUGH)
        assert result.worst_seconds == T.credential_ttl
        assert "credentials" in result.closed_by


class TestEngineEnforcement:
    @pytest.mark.parametrize("identity", list(IdentityMode))
    def test_bounded_by_the_decision_cache_whatever_the_connector_identity(
        self, identity: IdentityMode
    ) -> None:
        assert exposure(Pattern.ENGINE_ENFORCEMENT, identity).worst_seconds == T.decision_cache


class TestComparison:
    def test_with_shared_accounts_enforcing_where_the_person_is_visible_wins(self) -> None:
        shared = {p: exposure(p, IdentityMode.SERVICE_ACCOUNT) for p in Pattern}
        bounded = {p for p, e in shared.items() if not e.never_closes}
        assert bounded == {Pattern.MIRROR, Pattern.ENGINE_ENFORCEMENT}

    def test_timings_are_inputs(self) -> None:
        slow = Timings(batch_sync=86_400)
        result = exposure_after_revocation(Scenario(Pattern.MIRROR, IdentityMode.SERVICE_ACCOUNT), slow)
        assert result.worst_seconds == 86_400

    def test_tables_cover_every_pattern(self) -> None:
        assert set(COVERAGE) == set(Pattern)
        assert exposure_table().count("\n") == 6
        for pattern in Pattern:
            assert pattern.value in coverage_table()

    def test_never_is_rendered(self) -> None:
        assert "**never**" in exposure_table()
        assert not math.isinf(exposure(Pattern.MIRROR, IdentityMode.SERVICE_ACCOUNT).worst_seconds)
