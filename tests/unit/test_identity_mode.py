"""The platform backstop holds only when the platform sees the end user.

These tests are the reason the safety model is computed rather than asserted:
with a shared service account the same stale allow that passthrough catches
becomes a leak, and the model has to say so.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
import requests

from src.extractors.uc_to_ranger import ExtractionIncompleteError, UnityCatalogExtractor
from src.governance.safety_model import (
    STALENESS_SCENARIOS,
    AccessRequest,
    EnforcementState,
    IdentityMode,
    PlatformGrant,
    Principal,
    StalenessScenario,
    analyze_sync_gap,
    ranger_decision,
    simulate_request,
)

ALL_STATES = list(EnforcementState)


class TestIdentityModeChangesTheOutcome:
    def test_stale_allow_is_caught_with_passthrough(self) -> None:
        outcome = analyze_sync_gap(
            EnforcementState.STALE_ALLOW, EnforcementState.DENY, IdentityMode.PASSTHROUGH
        )
        assert outcome.access_granted is False
        assert outcome.outcome_type == "platform_backstop"

    def test_stale_allow_leaks_through_a_service_account(self) -> None:
        outcome = analyze_sync_gap(
            EnforcementState.STALE_ALLOW, EnforcementState.DENY, IdentityMode.SERVICE_ACCOUNT
        )
        assert outcome.access_granted is True
        assert outcome.is_safe is False
        assert outcome.outcome_type == "leak"

    @pytest.mark.parametrize("mode", list(IdentityMode))
    @pytest.mark.parametrize("service_reach", [True, False])
    def test_unsafe_exactly_when_an_unauthorized_user_gets_access(
        self, mode: IdentityMode, service_reach: bool
    ) -> None:
        for ranger, platform in itertools.product(ALL_STATES, ALL_STATES):
            outcome = analyze_sync_gap(ranger, platform, mode, service_reach)
            assert outcome.is_safe == (outcome.authorized or not outcome.access_granted)

    def test_passthrough_is_never_unsafe(self) -> None:
        for ranger, platform, reach in itertools.product(ALL_STATES, ALL_STATES, [True, False]):
            assert analyze_sync_gap(ranger, platform, IdentityMode.PASSTHROUGH, reach).is_safe

    def test_service_account_leaks_only_on_ranger_allow_with_user_denied(self) -> None:
        leaks = {
            (ranger, platform)
            for ranger, platform in itertools.product(ALL_STATES, ALL_STATES)
            if not analyze_sync_gap(ranger, platform, IdentityMode.SERVICE_ACCOUNT).is_safe
        }
        allows = {EnforcementState.ALLOW, EnforcementState.STALE_ALLOW}
        denies = {EnforcementState.DENY, EnforcementState.STALE_DENY}
        assert leaks == set(itertools.product(allows, denies))


class TestStalenessIsComputedFromState:
    def test_stale_allow_ranger_depends_on_identity_mode(self) -> None:
        scenario = STALENESS_SCENARIOS["stale_allow_ranger"]
        assert scenario.outcome_under(IdentityMode.PASSTHROUGH) == "fail-safe"
        assert scenario.outcome_under(IdentityMode.SERVICE_ACCOUNT) == "unsafe"

    @pytest.mark.parametrize("name", ["stale_extra_column", "stale_extra_table"])
    def test_dropped_objects_are_safe_in_either_mode(self, name: str) -> None:
        scenario = STALENESS_SCENARIOS[name]
        for mode in IdentityMode:
            assert scenario.is_safe_under(mode)

    def test_the_name_does_not_decide_the_outcome(self) -> None:
        misleading = StalenessScenario(
            name="stale_extra_but_actually_missing",
            description="",
            reason="",
            ranger_state=EnforcementState.STALE_DENY,
            platform_state=EnforcementState.ALLOW,
        )
        assert misleading.outcome == "fail-closed"


# ---------------------------------------------------------------------------
# End to end over the Unity Catalog extractor's real output
# ---------------------------------------------------------------------------

ANALYST = Principal("analyst@example.com", frozenset({"risk_analysts"}))
SERVICE = Principal("trino-connector@example.com")


def _uc_grant(principal: str, privilege: str, level: str, schema: str, table: str) -> dict[str, Any]:
    return {
        "principal": principal,
        "privilege": privilege,
        "catalog": "prod",
        "schema": schema,
        "table": table,
        "columns": ["*"],
        "level": level,
        "inherited": None,
        "source": "unity_catalog",
    }


@pytest.fixture
def mirrored_policies() -> list[dict[str, Any]]:
    """What Ranger holds after the last sync: the analyst could read risk.exposures."""
    extractor = UnityCatalogExtractor()
    return extractor._grants_to_ranger_policies(
        [
            _uc_grant(ANALYST.name, "SELECT", "table", "risk", "exposures"),
            _uc_grant(SERVICE.name, "SELECT", "catalog", "*", "*"),
        ]
    )


def _request(table: str = "exposures") -> AccessRequest:
    return AccessRequest(ANALYST, catalog="databricks", schema="risk", table=table)


class TestSimulationOverExtractedPolicies:
    # Unity Catalog today: the analyst's grant was revoked after the last sync.
    platform_now = [PlatformGrant(SERVICE.name, "databricks", "*", "*")]

    def test_revocation_is_enforced_with_passthrough(self, mirrored_policies: list[dict[str, Any]]) -> None:
        outcome = simulate_request(
            _request(), mirrored_policies, self.platform_now, IdentityMode.PASSTHROUGH, SERVICE
        )
        assert outcome.outcome_type == "platform_backstop"
        assert outcome.access_granted is False

    def test_revocation_is_bypassed_through_the_service_account(
        self, mirrored_policies: list[dict[str, Any]]
    ) -> None:
        outcome = simulate_request(
            _request(), mirrored_policies, self.platform_now, IdentityMode.SERVICE_ACCOUNT, SERVICE
        )
        assert outcome.outcome_type == "leak"

    def test_current_grant_is_authorized_in_either_mode(self, mirrored_policies: list[dict[str, Any]]) -> None:
        platform = [*self.platform_now, PlatformGrant(ANALYST.name, "databricks", "risk", "exposures")]
        for mode in IdentityMode:
            outcome = simulate_request(_request(), mirrored_policies, platform, mode, SERVICE)
            assert outcome.outcome_type == "authorized"

    def test_catalog_grant_covers_every_schema(self, mirrored_policies: list[dict[str, Any]]) -> None:
        anywhere = AccessRequest(SERVICE, catalog="databricks", schema="treasury", table="positions")
        assert ranger_decision(mirrored_policies, anywhere)

    def test_unmirrored_table_is_denied(self, mirrored_policies: list[dict[str, Any]]) -> None:
        assert not ranger_decision(mirrored_policies, _request("counterparties"))


# ---------------------------------------------------------------------------
# Unity Catalog extractor: never grant more than the source
# ---------------------------------------------------------------------------


class TestUnityCatalogMapping:
    def test_unmapped_privileges_grant_nothing(self) -> None:
        policies = UnityCatalogExtractor()._grants_to_ranger_policies(
            [
                _uc_grant("auditor@example.com", "BROWSE", "table", "risk", "exposures"),
                _uc_grant("auditor@example.com", "APPLY_TAG", "table", "risk", "exposures"),
            ]
        )
        assert policies == []

    def test_service_principals_are_users(self) -> None:
        app_id = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b"
        [policy] = UnityCatalogExtractor()._grants_to_ranger_policies(
            [_uc_grant(app_id, "SELECT", "table", "risk", "exposures")]
        )
        assert policy["policyItems"][0]["users"] == [app_id]
        assert policy["policyItems"][0]["groups"] == []


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class TestUnityCatalogReads:
    def test_lists_every_page(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pages = {
            None: {"schemas": [{"name": "risk"}], "next_page_token": "p2"},
            "p2": {"schemas": [{"name": "treasury"}, {"name": "information_schema"}]},
        }
        extractor = UnityCatalogExtractor()
        monkeypatch.setattr(
            extractor._session,
            "get",
            lambda url, params, timeout: _Response(pages[params.get("page_token")]),
        )
        assert extractor._discover_schemas() == ["risk", "treasury"]

    def test_a_failed_permission_read_stops_the_extraction(self, monkeypatch: pytest.MonkeyPatch) -> None:
        extractor = UnityCatalogExtractor()

        def fail(*args: Any, **kwargs: Any) -> Any:
            raise requests.ConnectionError("unreachable")

        monkeypatch.setattr(extractor._session, "get", fail)
        with pytest.raises(ExtractionIncompleteError):
            extractor._get_table_permissions("risk", "exposures")
