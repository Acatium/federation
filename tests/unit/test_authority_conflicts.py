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
from src.sync.federated import FederatedSync, Table, combine_authorities
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
        [combined] = combine_authorities(
            [_policy("lake_formation", "all", ["auditors"]), _policy("glue_iam", "select", ["auditors"])],
            sources=["lake_formation", "glue_iam"],
        )
        assert combined["policyItems"][0]["accesses"] == [{"type": "select", "isAllowed": True}]

    def test_deny_items_from_either_source_survive(self) -> None:
        deny = {**_policy("glue_iam", "select", []), "denyPolicyItems": [{"users": ["x"], "accesses": [{"type": "select"}]}]}
        [combined] = combine_authorities(
            [_policy("lake_formation", "select", ["auditors"]), deny], sources=["lake_formation", "glue_iam"]
        )
        assert combined["denyPolicyItems"] == deny["denyPolicyItems"]


def _policy(
    origin: str, access: str, groups: list[str], table: str = TABLE, columns: list[str] | None = None,
    schema: str = "federation_demo", catalog: str = "hive",
) -> dict[str, Any]:
    return {
        "name": f"{origin}_{table}", "service": "dev_trino", "policyType": 0, "isEnabled": True,
        "resources": {
            "catalog": {"values": [catalog]}, "schema": {"values": [schema]},
            "table": {"values": [table]}, "column": {"values": columns or ["*"]},
        },
        "policyItems": [{"users": [], "groups": groups, "accesses": [{"type": access, "isAllowed": True}]}],
        "policyLabels": [f"origin:{origin}", f"source:{origin}"],
    }


def _read(policies: list[dict[str, Any]], role: str, table: str = TABLE) -> bool:
    return ranger_decision(policies, AccessRequest(Principal(f"{role}-member", frozenset({role})), "hive", "federation_demo", table))


AWS = ["lake_formation", "glue_iam"]


class TestAndAcrossScopesAndSilence:
    def test_an_authority_with_nothing_to_allow_denies(self) -> None:
        # Lake Formation allows auditors on the table; IAM is silent on it.
        policies = combine_authorities(
            [_policy("lake_formation", "select", ["auditors"]), _policy("glue_iam", "select", ["auditors"], table="other")],
            sources=AWS,
        )
        assert not _read(policies, "auditors")

    def test_a_database_level_grant_is_anded_with_table_level_policies(self) -> None:
        policies = combine_authorities(
            [_policy("lake_formation", "select", ["analysts"], table="*"), _policy("glue_iam", "select", ["auditors"])],
            sources=AWS,
        )
        assert not _read(policies, "analysts")
        assert not _read(policies, "auditors")

    def test_broad_grants_reach_only_tables_every_authority_allows(self) -> None:
        policies = combine_authorities(
            [_policy("lake_formation", "select", ["auditors"], table="*"), _policy("glue_iam", "select", ["auditors"])],
            sources=AWS,
            tables=[Table("hive", "federation_demo", "unlisted")],
        )
        assert _read(policies, "auditors")
        assert not _read(policies, "auditors", table="unlisted")

    def test_column_grants_are_intersected(self) -> None:
        policies = combine_authorities(
            [
                _policy("lake_formation", "select", ["auditors"], columns=["amount", "entry_id"]),
                _policy("glue_iam", "select", ["auditors"]),
            ],
            sources=AWS,
        )
        [combined] = [p for p in policies if p["name"].startswith("and_")]
        assert combined["resources"]["column"]["values"] == ["amount", "entry_id"]

    def test_combined_names_are_unique_per_resource(self) -> None:
        policies = combine_authorities(
            [
                _policy("lake_formation", "select", ["auditors"], table="*"),
                _policy("glue_iam", "select", ["auditors"], table="ledger_entries"),
                _policy("glue_iam", "select", ["auditors"], table="ledger_entries_cold"),
            ],
            sources=AWS,
        )
        names = [p["name"] for p in policies if p["name"].startswith("and_")]
        assert len(names) == len(set(names)) == 2


class TestFailuresFailClosedWhereTheyApply:
    def _sources(self, failing: str) -> dict[str, Any]:
        def boom() -> list[dict[str, Any]]:
            raise RuntimeError("source unreachable")

        extract = {
            "lake_formation": lambda: [_policy("lake_formation", "select", ["auditors"])],
            "glue_iam": lambda: [_policy("glue_iam", "select", ["auditors"])],
            "unity_catalog": lambda: [_policy("unity_catalog", "select", ["auditors"], catalog="databricks", schema="risk")],
        }
        extract[failing] = boom
        return extract

    def test_a_failed_authority_denies_what_it_governs_jointly(self) -> None:
        sync = FederatedSync(self._sources("glue_iam"))
        policies = sync.extract_policies()
        assert sync.failed_origins == ["glue_iam"]
        assert not _read(policies, "auditors")

    def test_uninvolved_sources_keep_syncing(self) -> None:
        policies = FederatedSync(self._sources("glue_iam")).extract_policies()
        request = AccessRequest(Principal("m", frozenset({"auditors"})), "databricks", "risk", TABLE)
        assert ranger_decision(policies, request)

    def test_a_failed_registered_only_authority_is_assumed_to_govern_its_catalogs(self) -> None:
        def boom() -> list[dict[str, Any]]:
            raise RuntimeError("immuta down")

        sync = FederatedSync(
            {
                "redshift": lambda: [_policy("redshift", "select", ["auditors"], catalog="redshift", schema="federation")],
                "immuta": boom,
            }
        )
        request = AccessRequest(Principal("m", frozenset({"auditors"})), "redshift", "federation", TABLE)
        assert not ranger_decision(sync.extract_policies(), request)


class TestMigrationFromPerSourceSyncs:
    def test_leftover_per_source_policies_are_reconciled(self, ranger: _FakeRanger) -> None:
        ranger.policies[50] = {
            "id": 50, "name": "lf_old", "service": "dev_trino", "policyType": 0,
            "policyLabels": ["source:lake_formation"], "resources": _policy("x", "select", [])["resources"],
        }
        sync = _quiet(FederatedSync({"lake_formation": lambda: [_policy("lake_formation", "select", ["a"], table="t2")],
                                     "glue_iam": lambda: [_policy("glue_iam", "select", ["a"], table="t2")]}))
        sync.push_all(sync.extract_policies())
        result = sync.reconcile_removed({"dev_trino"})
        assert "lf_old" in result["deleted"]
        assert 50 not in ranger.policies


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
