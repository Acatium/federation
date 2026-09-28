"""Sync several sources that govern the same data, combining them by AND.

On AWS, reading a Lake Formation-governed table needs IAM and Lake Formation to
allow it; an Immuta policy sits on top of the platform's grants. Where several
authorities govern one resource, access is the intersection of what each allows.

Pushing each source separately cannot express that. Ranger accepts one access
policy per resource, so the second source's push hits the resource conflict and
overwrites the first: the last writer wins, and each sync flips the policy
between sources. ``FederatedSync`` extracts the sources together, combines
access policies that share a resource into their intersection, and pushes the
result once, under one owner, so reconciliation sees a single consistent set.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from src.extractors.base import BaseExtractor

Principal = tuple[str, str]  # ("user" | "group", name)


def _origin(policy: dict[str, Any]) -> str:
    for label in policy.get("policyLabels", []):
        if label.startswith("origin:"):
            return label.removeprefix("origin:")
    raise ValueError(f"policy {policy.get('name')!r} has no origin label")


def _allowed(policy: dict[str, Any]) -> dict[Principal, set[str]]:
    grants: dict[Principal, set[str]] = {}
    for item in policy.get("policyItems", []):
        types = {a["type"] for a in item.get("accesses", []) if a.get("isAllowed", True)}
        for user in item.get("users", []):
            grants.setdefault(("user", user), set()).update(types)
        for group in item.get("groups", []):
            grants.setdefault(("group", group), set()).update(types)
    return grants


def _intersect(a: set[str], b: set[str]) -> set[str]:
    if "all" in a:
        return set(b)
    if "all" in b:
        return set(a)
    return a & b


def combine_authorities(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine access policies from different origins that share a resource.

    A principal is allowed only if every origin allows it, with only the access
    types they all allow; deny items from any origin are kept. Principals are
    matched by name and kind, so a user allowed through a group in one source and
    directly in another is dropped: fail-closed, and labelled as a translation gap.
    Masking and row-filter policies pass through unchanged.
    """
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for policy in policies:
        groups.setdefault(BaseExtractor._resource_key(policy), []).append(policy)

    combined: list[dict[str, Any]] = []
    for members in groups.values():
        origins = sorted({_origin(p) for p in members})
        if len(origins) < 2 or members[0].get("policyType", 0) != 0:
            combined.extend(members)
            continue

        per_origin: dict[str, dict[Principal, set[str]]] = {}
        for policy in members:
            merged = per_origin.setdefault(_origin(policy), {})
            for principal, types in _allowed(policy).items():
                merged.setdefault(principal, set()).update(types)

        shared = set.intersection(*(set(g) for g in per_origin.values()))
        items = []
        for kind, name in sorted(shared):
            types = per_origin[origins[0]][(kind, name)]
            for origin in origins[1:]:
                types = _intersect(types, per_origin[origin][(kind, name)])
            if types:
                items.append(
                    {
                        "users": [name] if kind == "user" else [],
                        "groups": [name] if kind == "group" else [],
                        "accesses": [{"type": t, "isAllowed": True} for t in sorted(types)],
                    }
                )

        policy = copy.deepcopy(members[0])
        resources = policy["resources"]
        slug = "_".join(
            resources[r]["values"][0].replace("*", "all") for r in ("catalog", "schema", "table") if r in resources
        )
        policy["name"] = f"and_{'_'.join(origins)}_{slug}"
        policy["policyItems"] = items
        policy["denyPolicyItems"] = [i for p in members for i in p.get("denyPolicyItems", [])]
        labels = {label for p in members for label in p.get("policyLabels", [])}
        labels.add(f"combined:and({'+'.join(origins)})")
        policy["policyLabels"] = sorted(labels)
        combined.append(policy)
    return combined


class FederatedSync(BaseExtractor):
    """Extract several sources together and push their combined policies once."""

    def __init__(self, sources: dict[str, Callable[[], list[dict[str, Any]]]]) -> None:
        super().__init__(source_name="federated_sync")
        self.sources = sources

    def extract_policies(self) -> list[dict[str, Any]]:
        own = self._base_labels()
        tagged: list[dict[str, Any]] = []
        for origin, extract in self.sources.items():
            for policy in extract():
                policy = copy.deepcopy(policy)
                kept = [label for label in policy.get("policyLabels", []) if not label.startswith("source:")]
                policy["policyLabels"] = [*own, f"origin:{origin}", *kept]
                tagged.append(policy)
        return combine_authorities(tagged)
