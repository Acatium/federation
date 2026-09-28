"""Two authorities over the same data combine by AND; a per-source mirror cannot.

On AWS, reading a Lake Formation-governed table needs IAM and Lake Formation to
allow it. Here Lake Formation allows analysts and auditors; IAM allows auditors
and contractors. Only auditors can read the table at the source.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.extractors.glue_iam_to_ranger import GlueIamExtractor
from src.extractors.lf_to_ranger import LakeFormationExtractor
from src.governance.safety_model import AccessRequest, Principal, ranger_decision
from src.sync.federated import FederatedSync, combine_authorities
from tests.unit.test_identity_mode import _FakeRanger, ranger  # noqa: F401  (fixture)

ACCOUNT = "111122223333"
TABLE = "ledger_entries"


def _role(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def _lf_policies() -> list[dict[str, Any]]:
    grants = [
        {
            "principal": _role(role), "privilege": "SELECT", "grantable": False,
            "database": "federation_demo", "table": TABLE, "columns": ["*"],
            "level": "table", "source": "lake_formation",
        }
        for role in ("analysts", "auditors")
    ]
    return LakeFormationExtractor()._grants_to_ranger_policies(grants)


def _iam_policies() -> list[dict[str, Any]]:
    return GlueIamExtractor()._parse_resource_statement(
        {
            "Effect": "Allow",
            "Principal": {"AWS": [_role("auditors"), _role("contractors")]},
            "Action": ["glue:GetTable"],
            "Resource": [f"arn:aws:glue:us-east-2:{ACCOUNT}:table/federation_demo/{TABLE}"],
        }
    )


def _can_read(role: str, ranger: _FakeRanger) -> bool:
    request = AccessRequest(Principal(f"{role}-member", frozenset({role})), "hive", "federation_demo", TABLE)
    return ranger_decision(list(ranger.policies.values()), request)


def _quiet(extractor: Any) -> Any:
    extractor._check_zones_configured = lambda: False
    extractor._ensure_ranger_principals = lambda policies: None
    return extractor


class TestSeparateRunsLetTheLastSourceWin:
    """What happens today when each extractor pushes on its own."""

    @pytest.fixture(autouse=True)
    def _region(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AWS_REGION", "us-east-2")

    def test_iam_last_lets_contractors_in_and_locks_analysts_out(self, ranger: _FakeRanger) -> None:
        _quiet(LakeFormationExtractor()).push_all(_lf_policies())
        _quiet(GlueIamExtractor()).push_all(_iam_policies())
        assert _can_read("contractors", ranger)  # IAM allows; Lake Formation does not
        assert not _can_read("analysts", ranger)

    def test_the_answer_flips_with_the_order(self, ranger: _FakeRanger) -> None:
        _quiet(GlueIamExtractor()).push_all(_iam_policies())
        _quiet(LakeFormationExtractor()).push_all(_lf_policies())
        assert _can_read("analysts", ranger)  # Lake Formation allows; IAM does not
        assert not _can_read("contractors", ranger)


class TestFederatedSyncCombinesByAnd:
    @pytest.fixture(autouse=True)
    def _region(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AWS_REGION", "us-east-2")

    @pytest.mark.parametrize("order", [("lake_formation", "glue_iam"), ("glue_iam", "lake_formation")])
    def test_only_principals_every_authority_allows_can_read(
        self, ranger: _FakeRanger, order: tuple[str, str]
    ) -> None:
        extract = {"lake_formation": _lf_policies, "glue_iam": _iam_policies}
        sync = _quiet(FederatedSync({name: extract[name] for name in order}))
        sync.push_all(sync.extract_policies())
        assert sync.policies_failed == 0
        assert _can_read("auditors", ranger)
        assert not _can_read("analysts", ranger)
        assert not _can_read("contractors", ranger)

    def test_the_combined_policy_is_labelled(self, ranger: _FakeRanger) -> None:
        sync = FederatedSync({"lake_formation": _lf_policies, "glue_iam": _iam_policies})
        [policy] = sync.extract_policies()
        assert "combined:and(glue_iam+lake_formation)" in policy["policyLabels"]
        assert "source:federated_sync" in policy["policyLabels"]

    def test_all_intersects_to_the_other_sources_access(self) -> None:
        def policy(origin: str, access: str) -> dict[str, Any]:
            return {
                "name": origin, "service": "dev_trino", "policyType": 0,
                "resources": {"catalog": {"values": ["hive"]}, "schema": {"values": ["d"]}, "table": {"values": ["t"]}},
                "policyItems": [{"users": [], "groups": ["auditors"], "accesses": [{"type": access, "isAllowed": True}]}],
                "policyLabels": [f"origin:{origin}"],
            }

        [combined] = combine_authorities([policy("a", "all"), policy("b", "select")])
        assert combined["policyItems"][0]["accesses"] == [{"type": "select", "isAllowed": True}]

    def test_deny_items_from_either_source_survive(self) -> None:
        base = {
            "service": "dev_trino", "policyType": 0,
            "resources": {"catalog": {"values": ["hive"]}, "schema": {"values": ["d"]}, "table": {"values": ["t"]}},
        }
        a = {**base, "name": "a", "policyLabels": ["origin:a"], "policyItems": [], "denyPolicyItems": [{"users": ["x"]}]}
        b = {**base, "name": "b", "policyLabels": ["origin:b"], "policyItems": []}
        [combined] = combine_authorities([a, b])
        assert combined["denyPolicyItems"] == [{"users": ["x"]}]


class TestLakeFormationMapping:
    @pytest.fixture(autouse=True)
    def _region(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AWS_REGION", "us-east-2")

    def _accesses(self, privilege: str) -> list[str]:
        grant = {
            "principal": _role("readers"), "privilege": privilege, "grantable": False,
            "database": "federation_demo", "table": TABLE, "columns": ["*"],
            "level": "table", "source": "lake_formation",
        }
        policies = LakeFormationExtractor()._grants_to_ranger_policies([grant])
        return [a["type"] for p in policies for i in p["policyItems"] for a in i["accesses"]]

    def test_describe_is_metadata_not_a_read(self) -> None:
        assert self._accesses("DESCRIBE") == ["show"]

    @pytest.mark.parametrize("privilege", ["DATA_LOCATION_ACCESS", "SOMETHING_NEW"])
    def test_non_read_and_unknown_permissions_grant_nothing(self, privilege: str) -> None:
        assert self._accesses(privilege) == []
