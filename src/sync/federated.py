"""Sync several sources that govern the same data, combining them by AND.

On AWS, reading a Lake Formation-governed table needs IAM and Lake Formation to
allow it; an Immuta policy sits on top of the platform's grants. Where several
authorities govern one table, access is the intersection of what each allows,
and an authority that allows nothing on the table denies it.

Pushing each source separately cannot express that. Ranger holds one access
policy per resource, so the second source's push overwrites the first, and
separate allow policies on overlapping scopes (a database-level grant and a
table-level one) are ORed. ``FederatedSync`` therefore:

1. knows which sources govern which catalogs (``DEFAULT_AUTHORITIES``);
2. expands every access grant onto the concrete tables it covers, and for each
   table governed by more than one source computes the intersection per
   principal, per access type and per column set;
3. pushes the result once, under one owner, deleting what that owner, or the
   per-source syncs it replaces, left behind.

A source that fails to extract contributes no grants, so every table it governs
jointly is denied, and allows it governed alone are removed by reconciliation.
Other sources keep syncing.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from src.extractors.base import RANGER_SERVICE, BaseExtractor

logger = logging.getLogger(__name__)

ALL_COLUMNS = frozenset({"*"})


@dataclass(frozen=True)
class Authority:
    """A source that enforces access on some catalogs.

    ``registered_only`` authorities govern only tables they have registered (they
    appear in its policies), within ``catalogs``. If such a source fails, its
    registrations are unknown, so it is treated as governing all of ``catalogs``.
    """

    origin: str
    catalogs: tuple[str, ...]
    registered_only: bool = False


DEFAULT_AUTHORITIES: tuple[Authority, ...] = (
    Authority("lake_formation", ("hive",)),
    Authority("glue_iam", ("hive",)),
    Authority("redshift", ("redshift",)),
    Authority("snowflake", ("snowflake",)),
    Authority("unity_catalog", ("databricks",)),
    Authority("immuta", ("hive", "redshift", "snowflake"), registered_only=True),
)


@dataclass(frozen=True, order=True)
class Table:
    catalog: str
    schema: str
    table: str


Principal = tuple[str, str]  # ("user" | "group", name)
Grants = dict[Principal, dict[str, frozenset[str]]]  # principal -> access type -> columns


def _values(policy: dict[str, Any], resource: str) -> tuple[list[str], bool]:
    res = policy.get("resources", {}).get(resource, {"values": ["*"]})
    return res.get("values", ["*"]), bool(res.get("isExcludes"))


def _hits(policy: dict[str, Any], resource: str, value: str) -> bool:
    values, excludes = _values(policy, resource)
    hit = any(fnmatch.fnmatchcase(value.lower(), v.lower()) for v in values)
    return not hit if excludes else hit


def _covers(policy: dict[str, Any], table: Table) -> bool:
    return (
        _hits(policy, "catalog", table.catalog)
        and _hits(policy, "schema", table.schema)
        and _hits(policy, "table", table.table)
    )


def _concrete(policy: dict[str, Any]) -> list[Table]:
    """Tables a policy names outright (no wildcard, no exclusion)."""
    parts = [_values(policy, r) for r in ("catalog", "schema", "table")]
    if any(excl or any(ch in v for v in vals for ch in "*?") for vals, excl in parts):
        return []
    return [Table(c, s, t) for c in parts[0][0] for s in parts[1][0] for t in parts[2][0]]


def _origin(policy: dict[str, Any]) -> str:
    for label in policy.get("policyLabels", []):
        if label.startswith("origin:"):
            return label.removeprefix("origin:")
    raise ValueError(f"policy {policy.get('name')!r} has no origin label")


def _columns(policy: dict[str, Any]) -> frozenset[str]:
    values, excludes = _values(policy, "column")
    if excludes or "*" in values:
        # An excluded column list cannot be intersected safely here; treat as no
        # column restriction only when it is a plain "*".
        return ALL_COLUMNS if not excludes else frozenset()
    return frozenset(v.lower() for v in values)


def _grants(policies: Iterable[dict[str, Any]], table: Table) -> Grants:
    grants: Grants = {}
    for policy in policies:
        if not _covers(policy, table):
            continue
        columns = _columns(policy)
        for item in policy.get("policyItems", []):
            types = [a["type"] for a in item.get("accesses", []) if a.get("isAllowed", True)]
            principals = [("user", u) for u in item.get("users", [])] + [
                ("group", g) for g in item.get("groups", [])
            ]
            for principal in principals:
                access = grants.setdefault(principal, {})
                for t in types:
                    access[t] = _union_cols(access.get(t), columns)
    return grants


def _union_cols(a: frozenset[str] | None, b: frozenset[str]) -> frozenset[str]:
    if a is None:
        return b
    if a == ALL_COLUMNS or b == ALL_COLUMNS:
        return ALL_COLUMNS
    return a | b


def _and_cols(a: frozenset[str], b: frozenset[str]) -> frozenset[str]:
    if a == ALL_COLUMNS:
        return b
    if b == ALL_COLUMNS:
        return a
    return a & b


def _and_access(a: dict[str, frozenset[str]], b: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    result: dict[str, frozenset[str]] = {}
    if "all" in a and "all" in b:
        result["all"] = _and_cols(a["all"], b["all"])
    for t in (set(a) | set(b)) - {"all"}:
        left, right = a.get(t, a.get("all")), b.get(t, b.get("all"))
        if left is not None and right is not None:
            result[t] = _and_cols(left, right)
    return {t: cols for t, cols in result.items() if cols}


def combine_authorities(
    policies: list[dict[str, Any]],
    sources: Iterable[str],
    authorities: Iterable[Authority] = DEFAULT_AUTHORITIES,
    tables: Iterable[Table] = (),
    failed: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Combine origin-labelled policies so jointly governed tables get the AND.

    ``tables`` is an inventory of known tables. Grants reach a jointly governed
    table only if the table is known, from the inventory or because some policy
    names it; a wildcard grant over an unknown table gives no access there
    (fail-closed). Masking and row-filter policies pass through unchanged.
    """
    sources, failed = set(sources), set(failed)
    authorities = [a for a in authorities if a.origin in sources]
    access = [p for p in policies if p.get("policyType", 0) == 0]
    other = [p for p in policies if p.get("policyType", 0) != 0]

    known = set(tables) | {t for p in policies for t in _concrete(p)}
    registered = {
        o: {t for p in policies if _origin(p) == o for t in known if _covers(p, t)} for o in sources
    }

    def governors(table: Table) -> set[str]:
        declared = {
            a.origin
            for a in authorities
            if any(fnmatch.fnmatchcase(table.catalog, c) for c in a.catalogs)
            and (not a.registered_only or a.origin in failed or table in registered[a.origin])
        }
        return declared or {_origin(p) for p in access if _covers(p, table)}

    joint = {t for t in known if len(governors(t)) > 1}
    joint_catalogs = {
        c
        for a in authorities
        for c in a.catalogs
        if not a.registered_only
        and sum(1 for b in authorities if not b.registered_only and c in b.catalogs) > 1
    }

    def consumed(policy: dict[str, Any]) -> bool:
        catalogs, _ = _values(policy, "catalog")
        if any(fnmatch.fnmatchcase(jc, c) for c in catalogs for jc in joint_catalogs):
            return True
        return any(_covers(policy, t) for t in joint)

    passthrough = [p for p in access if not consumed(p)]
    taken = [p for p in access if consumed(p)]
    to_build = sorted(joint | {t for t in known for p in taken if _covers(p, t)})

    combined: list[dict[str, Any]] = []
    for table in to_build:
        gov = sorted(governors(table))
        per_origin = [_grants((p for p in taken + passthrough if _origin(p) == o), table) for o in gov]
        shared = set.intersection(*(set(g) for g in per_origin)) if per_origin else set()
        by_scope: dict[frozenset[str], dict[Principal, set[str]]] = {}
        for principal in shared:
            result = per_origin[0][principal]
            for other_grants in per_origin[1:]:
                result = _and_access(result, other_grants[principal])
            for t, cols in result.items():
                by_scope.setdefault(cols, {}).setdefault(principal, set()).add(t)

        denies = [
            item
            for p in taken + passthrough
            if _origin(p) in gov and _covers(p, table)
            for item in p.get("denyPolicyItems", [])
        ]
        scopes = set(by_scope) | ({ALL_COLUMNS} if denies else set())
        for cols in sorted(scopes, key=sorted):
            resources = {
                "catalog": {"values": [table.catalog]},
                "schema": {"values": [table.schema]},
                "table": {"values": [table.table]},
                "column": {"values": sorted(cols)},
            }
            digest = hashlib.sha1(repr(sorted((k, v["values"]) for k, v in resources.items())).encode()).hexdigest()
            items = [
                {
                    "users": [name] if kind == "user" else [],
                    "groups": [name] if kind == "group" else [],
                    "accesses": [{"type": t, "isAllowed": True} for t in sorted(types)],
                }
                for (kind, name), types in sorted(by_scope.get(cols, {}).items())
            ]
            combined.append(
                {
                    "policyType": 0,
                    "service": RANGER_SERVICE,
                    "name": f"and_{table.table}_{digest[:12]}",
                    "isEnabled": True,
                    "resources": resources,
                    "policyItems": items,
                    "denyPolicyItems": denies if cols == ALL_COLUMNS else [],
                    "policyLabels": sorted(
                        {label for p in taken if _covers(p, table) for label in p.get("policyLabels", [])}
                        | {f"combined:and({'+'.join(gov)})"}
                        | ({f"origin_failed:{o}" for o in gov if o in failed})
                    ),
                }
            )
    return passthrough + combined + other


class FederatedSync(BaseExtractor):
    """Extract several sources together and push their combined policies once."""

    def __init__(
        self,
        sources: dict[str, Callable[[], list[dict[str, Any]]]],
        authorities: Iterable[Authority] = DEFAULT_AUTHORITIES,
        tables: Callable[[], Iterable[Table]] | None = None,
    ) -> None:
        super().__init__(source_name="federated_sync")
        self.sources = sources
        self.authorities = tuple(authorities)
        self.tables = tables
        self.failed_origins: list[str] = []

    def _owned_labels(self) -> set[str]:
        # Also the labels the per-source syncs used, so their leftovers are reconciled.
        return {f"source:{self.source_name}", *(f"source:{o}" for o in self.sources)}

    def extract_policies(self) -> list[dict[str, Any]]:
        own = [label for label in self._base_labels() if label.startswith("source:")]
        tagged: list[dict[str, Any]] = []
        self.failed_origins = []
        for origin, extract in self.sources.items():
            try:
                extracted = extract()
            except Exception as exc:
                logger.error("Source %s failed to extract; failing closed where it governs: %s", origin, exc)
                self.failed_origins.append(origin)
                continue
            for policy in extracted:
                policy = copy.deepcopy(policy)
                kept = [label for label in policy.get("policyLabels", []) if not label.startswith("source:")]
                policy["policyLabels"] = [*own, f"origin:{origin}", *kept]
                tagged.append(policy)
        tables = list(self.tables()) if self.tables else []
        combined = combine_authorities(tagged, self.sources, self.authorities, tables, self.failed_origins)
        for policy in combined:
            labels = policy.setdefault("policyLabels", [])
            for label in own:
                if label not in labels:
                    labels.append(label)
        return combined

    def extract_and_push(self) -> dict[str, Any]:
        summary = super().extract_and_push()
        summary["failed_origins"] = list(self.failed_origins)
        if self.failed_origins and summary.get("status") == "complete":
            summary["status"] = "partial"
        return summary
