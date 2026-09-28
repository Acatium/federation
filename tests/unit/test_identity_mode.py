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
        assert misleading.outcome_under(IdentityMode.PASSTHROUGH) == "fail-closed"


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


def _policy(**overrides: Any) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "policyType": 0,
        "isEnabled": True,
        "resources": {
            "catalog": {"values": ["databricks"]},
            "schema": {"values": ["risk"]},
            "table": {"values": ["*"]},
            "column": {"values": ["*"]},
        },
        "policyItems": [{"users": [ANALYST.name], "groups": [], "accesses": [{"type": "select", "isAllowed": True}]}],
    }
    policy.update(overrides)
    return policy


class TestRangerEvaluation:
    def test_wildcard_patterns_match(self) -> None:
        policy = _policy()
        policy["resources"]["table"] = {"values": ["expo*"]}
        assert ranger_decision([policy], _request("exposures"))
        assert not ranger_decision([policy], _request("counterparties"))

    def test_is_excludes_inverts_the_match(self) -> None:
        policy = _policy()
        policy["resources"]["table"] = {"values": ["exposures"], "isExcludes": True}
        assert not ranger_decision([policy], _request("exposures"))
        assert ranger_decision([policy], _request("counterparties"))

    def test_allow_exceptions_remove_the_allow(self) -> None:
        policy = _policy(allowExceptions=[{"users": [ANALYST.name], "accesses": [{"type": "select"}]}])
        assert not ranger_decision([policy], _request())

    def test_deny_wins_unless_excepted(self) -> None:
        deny = [{"groups": ["risk_analysts"], "accesses": [{"type": "select"}]}]
        assert not ranger_decision([_policy(denyPolicyItems=deny)], _request())
        excepted = _policy(
            denyPolicyItems=deny,
            denyExceptions=[{"users": [ANALYST.name], "accesses": [{"type": "select"}]}],
        )
        assert ranger_decision([excepted], _request())


class TestUnityCatalogPermissionPages:
    def test_reads_every_page_of_grants(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pages = {
            None: {"privilege_assignments": [{"principal": "a@example.com", "privileges": ["SELECT"]}], "next_page_token": "p2"},
            "p2": {"privilege_assignments": [{"principal": "b@example.com", "privileges": ["SELECT"]}]},
        }
        extractor = UnityCatalogExtractor()
        monkeypatch.setattr(
            extractor._session,
            "get",
            lambda url, params, timeout: _Response(pages[params.get("page_token")]),
        )
        grants = extractor._get_table_permissions("risk", "exposures")
        assert {g["principal"] for g in grants} == {"a@example.com", "b@example.com"}


# ---------------------------------------------------------------------------
# Sync must delete what the source stopped granting
# ---------------------------------------------------------------------------


class _HTTP:
    def __init__(self, payload: Any = None, status: int = 200, text: str = "") -> None:
        self._payload, self.status_code, self.text = payload, status, text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(self.text, response=self)  # type: ignore[arg-type]

    def json(self) -> Any:
        return self._payload


class _FakeRanger:
    """Ranger's public v2 policy API, as push and reconcile use it.

    Like Ranger, it pages policy searches and rejects a second policy for the
    same resources with a 400 naming the existing policy.
    """

    def __init__(self, page_size: int = 200) -> None:
        self.policies: dict[int, dict[str, Any]] = {}
        self.page_size = page_size
        self._next = 1

    def get(self, url: str, params: dict[str, Any], auth: Any = None, timeout: int = 0) -> _HTTP:
        found = [p for p in self.policies.values() if p.get("service") == params.get("serviceName")]
        if "policyName" in params:
            return _HTTP([p for p in found if p["name"] == params["policyName"]])
        start = int(params.get("startIndex", 0))
        size = min(int(params.get("pageSize", self.page_size)), self.page_size)
        return _HTTP(sorted(found, key=lambda p: p["id"])[start : start + size])

    def post(self, url: str, json: dict[str, Any], auth: Any = None, timeout: int = 0) -> _HTTP:
        for existing in self.policies.values():
            if existing["resources"] == json["resources"] and existing.get("service") == json.get("service"):
                msg = f"Another policy already exists for matching resource: policy-name=[{existing['name']}]"
                return _HTTP(status=400, text=msg)
        policy = {**json, "id": self._next}
        self.policies[self._next] = policy
        self._next += 1
        return _HTTP(policy)

    def put(self, url: str, json: dict[str, Any], auth: Any = None, timeout: int = 0) -> _HTTP:
        policy_id = int(url.rsplit("/", 1)[1])
        self.policies[policy_id] = {**json, "id": policy_id}
        return _HTTP(self.policies[policy_id])

    def delete(self, url: str, auth: Any = None, timeout: int = 0) -> _HTTP:
        del self.policies[int(url.rsplit("/", 1)[1])]
        return _HTTP({})

    def users_on(self, table: str) -> set[str]:
        return {
            user
            for p in self.policies.values()
            if table in p["resources"]["table"]["values"]
            for item in p.get("policyItems", [])
            for user in item.get("users", [])
        }


@pytest.fixture
def ranger(monkeypatch: pytest.MonkeyPatch) -> _FakeRanger:
    import src.extractors.base as base

    fake = _FakeRanger()
    for verb in ("get", "post", "put", "delete"):
        monkeypatch.setattr(base.requests, verb, getattr(fake, verb))
    return fake


def _sync(grants: list[dict[str, Any]]) -> dict[str, list[str]]:
    """One extractor run: push the merged policies, then reconcile."""
    extractor = UnityCatalogExtractor()
    extractor._check_zones_configured = lambda: False  # type: ignore[method-assign]
    extractor._ensure_ranger_principals = lambda policies: None  # type: ignore[method-assign]
    policies = [{**p, "service": "dev_trino"} for p in extractor._grants_to_ranger_policies(grants)]
    extractor.push_all(policies)
    assert extractor.policies_failed == 0
    return extractor.reconcile_removed({"dev_trino"})


A, B = "a@example.com", "b@example.com"


class TestReconciliation:
    def test_revoking_the_first_named_grantee_keeps_the_others_policy(self, ranger: _FakeRanger) -> None:
        _sync([_uc_grant(A, "SELECT", "table", "risk", "exposures"), _uc_grant(B, "SELECT", "table", "risk", "exposures")])
        assert ranger.users_on("exposures") == {A, B}
        _sync([_uc_grant(B, "SELECT", "table", "risk", "exposures")])
        assert ranger.users_on("exposures") == {B}

    def test_a_resources_last_grant_disappearing_deletes_its_policy(self, ranger: _FakeRanger) -> None:
        _sync([_uc_grant(A, "SELECT", "table", "risk", "exposures"), _uc_grant(B, "SELECT", "table", "risk", "positions")])
        result = _sync([_uc_grant(B, "SELECT", "table", "risk", "positions")])
        assert len(result["deleted"]) == 1
        assert ranger.users_on("exposures") == set()
        assert ranger.users_on("positions") == {B}

    def test_stale_policies_beyond_the_first_page_are_found(
        self, ranger: _FakeRanger, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import src.extractors.base as base

        monkeypatch.setattr(base, "RANGER_PAGE_SIZE", 2)
        ranger.page_size = 2
        tables = [f"t{i}" for i in range(5)]
        _sync([_uc_grant(A, "SELECT", "table", "risk", t) for t in tables])
        _sync([_uc_grant(A, "SELECT", "table", "risk", "t0")])
        assert [t for t in tables if ranger.users_on(t)] == ["t0"]

    def test_other_sources_are_left_alone(self, ranger: _FakeRanger) -> None:
        ranger.policies[99] = {
            "id": 99, "name": "sf", "service": "dev_trino", "policyType": 0,
            "policyLabels": ["source:snowflake"], "resources": {"table": {"values": ["x"]}},
        }
        _sync([_uc_grant(A, "SELECT", "table", "risk", "exposures")])
        assert 99 in ranger.policies

    def test_removed_masking_and_deny_policies_are_reported_not_deleted(self, ranger: _FakeRanger) -> None:
        label = ["source:unity_catalog"]
        ranger.policies[98] = {"id": 98, "name": "mask", "service": "dev_trino", "policyType": 1, "policyLabels": label, "resources": {}}
        ranger.policies[97] = {
            "id": 97, "name": "deny", "service": "dev_trino", "policyType": 0,
            "policyLabels": label, "denyPolicyItems": [{}], "resources": {},
        }
        result = _sync([_uc_grant(A, "SELECT", "table", "risk", "exposures")])
        assert sorted(result["needs_review"]) == ["deny", "mask"]
        assert {97, 98} <= set(ranger.policies)

    def test_merging_does_not_mutate_its_input(self) -> None:
        extractor = UnityCatalogExtractor()
        policies = extractor._grants_to_ranger_policies(
            [_uc_grant(A, "SELECT", "table", "risk", "exposures"), _uc_grant(B, "SELECT", "table", "risk", "exposures")]
        )
        before = [len(p["policyItems"]) for p in policies]
        extractor._merge_by_resource(policies)
        assert [len(p["policyItems"]) for p in policies] == before
