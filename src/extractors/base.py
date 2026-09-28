"""Base class for all policy extractors.

Provides common Ranger REST API interaction (push, update, idempotent upsert),
policy construction helpers, drift detection, and contract output logic. All
concrete extractors inherit from BaseExtractor.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

from src.utils.config import CONTRACTS_DIR, PROJECT_ROOT

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RANGER_HOST: str = os.getenv("RANGER_HOST", "localhost")
_RANGER_PORT: str = os.getenv("RANGER_PORT", "6080")
_RANGER_SCHEME: str = os.getenv("RANGER_SCHEME", "http")

RANGER_BASE_URL: str = f"{_RANGER_SCHEME}://{_RANGER_HOST}:{_RANGER_PORT}"

_RANGER_ADMIN_PASSWORD: str = os.getenv("RANGER_ADMIN_PASSWORD", "")
if _RANGER_HOST != "localhost" and not _RANGER_ADMIN_PASSWORD:
    logger.warning(
        "RANGER_ADMIN_PASSWORD is empty — Ranger API calls will fail. "
        "Set RANGER_ADMIN_PASSWORD in your .env file."
    )

RANGER_AUTH: tuple[str, str] = (
    os.getenv("RANGER_ADMIN_USER", "admin"),
    _RANGER_ADMIN_PASSWORD,
)
RANGER_SERVICE: str = os.getenv("RANGER_SERVICE", "dev_trino")
RANGER_API: str = f"{RANGER_BASE_URL}/service/public/v2/api"
# Ranger's policy search returns one page (server default ranger.db.maxrows.default).
RANGER_PAGE_SIZE: int = 200

# Table inventory — sanitised names used across all extractors
DEMO_DATABASE: str = "federation_demo"
DEMO_TABLES: list[str] = [
    "ledger_entries",
    "entities",
    "risk_signals",
    "counterparty_ref",
]

# PII columns per table (from schemas.py column definitions)
PII_COLUMNS: dict[str, list[str]] = {
    "ledger_entries": ["token_id", "account_ref", "entity_name"],
    "entities": ["entity_name", "account_ref"],
    "risk_signals": [],
    "counterparty_ref": [],
}


_SNAPSHOTS_DIR: Path = PROJECT_ROOT / "data" / "snapshots"


class BaseExtractor(ABC):
    """Abstract base class for platform-to-Ranger policy extractors."""

    def __init__(self, source_name: str) -> None:
        self.source_name: str = source_name
        self.policies_pushed: int = 0
        self.policies_failed: int = 0
        self._aborted: bool = False
        self._extraction_ts: str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._zones_configured: bool | None = None  # lazy-loaded
        self._written_ids: set[int] = set()  # Ranger ids created or updated this run

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def extract_policies(self) -> list[dict[str, Any]]:
        """Connect to the source platform and return a list of Ranger-format policies."""
        ...

    # ------------------------------------------------------------------
    # Ranger push helpers
    # ------------------------------------------------------------------

    def _check_zones_configured(self) -> bool:
        """Check if Ranger Security Zones are configured (cached).

        Returns:
            True if at least one non-default zone exists.
        """
        if self._zones_configured is not None:
            return self._zones_configured

        try:
            resp = requests.get(
                f"{RANGER_API}/zones",
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code == 200:
                zones = resp.json()
                # Filter out empty or default-only responses
                if isinstance(zones, list):
                    self._zones_configured = len(zones) > 0
                else:
                    self._zones_configured = False
            else:
                self._zones_configured = False
        except requests.RequestException:
            self._zones_configured = False

        return self._zones_configured

    def _record_written(self, policy_id: Any) -> None:
        if isinstance(policy_id, int):
            self._written_ids.add(policy_id)

    def push_policy(self, policy: dict[str, Any]) -> bool:
        """Create or update a single Ranger policy (idempotent by policy name).

        If a POST fails because another policy with the same resource signature
        already exists, the conflicting policy is found and updated instead.

        Returns True on success, False on failure.
        """
        policy_name = policy.get("name", "<unnamed>")
        service_name = policy.get("service", RANGER_SERVICE)

        # S7: Zone conflict guard — warn if zones are configured but policy has no zoneName
        if self._check_zones_configured() and not policy.get("zoneName"):
            logger.warning(
                "Policy '%s' has no zoneName — will land in default zone. "
                "Resources in security zones will not see this policy.",
                policy_name,
            )

        try:
            # Check if the policy already exists by name
            resp = requests.get(
                f"{RANGER_API}/policy",
                params={"serviceName": service_name, "policyName": policy_name},
                auth=RANGER_AUTH,
                timeout=30,
            )
            resp.raise_for_status()
            existing = resp.json()

            if existing:
                # Update existing policy
                policy_id = existing[0]["id"]
                old_type = existing[0].get("policyType", 0)
                new_type = policy.get("policyType", 0)

                if old_type != new_type:
                    # Ranger does not allow changing policyType on an existing
                    # policy.  Delete the old one and create fresh.
                    logger.info(
                        "Policy '%s' id=%s type changed %d→%d — deleting old, creating new.",
                        policy_name, policy_id, old_type, new_type,
                    )
                    del_resp = requests.delete(
                        f"{RANGER_API}/policy/{policy_id}",
                        auth=RANGER_AUTH,
                        timeout=30,
                    )
                    del_resp.raise_for_status()
                    policy.pop("id", None)
                    post_resp = requests.post(
                        f"{RANGER_API}/policy",
                        json=policy,
                        auth=RANGER_AUTH,
                        timeout=30,
                    )
                    post_resp.raise_for_status()
                    new_id = post_resp.json().get("id", "?")
                    self._record_written(new_id)
                    logger.info(
                        "Recreated policy id=%s name='%s' (type %d→%d)",
                        new_id, policy_name, old_type, new_type,
                    )
                else:
                    policy["id"] = policy_id
                    put_resp = requests.put(
                        f"{RANGER_API}/policy/{policy_id}",
                        json=policy,
                        auth=RANGER_AUTH,
                        timeout=30,
                    )
                    put_resp.raise_for_status()
                    self._record_written(policy_id)
                    logger.info("Updated Ranger policy id=%s name='%s'", policy_id, policy_name)
            else:
                # Create new policy
                post_resp = requests.post(
                    f"{RANGER_API}/policy",
                    json=policy,
                    auth=RANGER_AUTH,
                    timeout=30,
                )
                if post_resp.status_code == 400:
                    err_body = post_resp.text
                    # Handle resource-signature conflict by updating existing
                    if "Another policy already exists for matching resource" in err_body:
                        match = re.search(r"policy-name=\[([^\]]+)\]", err_body)
                        if match:
                            conflicting_name = match.group(1)
                            logger.info(
                                "Resource conflict: '%s' conflicts with '%s'. Updating existing.",
                                policy_name,
                                conflicting_name,
                            )
                            conflict_resp = requests.get(
                                f"{RANGER_API}/policy",
                                params={
                                    "serviceName": service_name,
                                    "policyName": conflicting_name,
                                },
                                auth=RANGER_AUTH,
                                timeout=30,
                            )
                            conflict_resp.raise_for_status()
                            conflict_policies = conflict_resp.json()
                            if conflict_policies:
                                cid = conflict_policies[0]["id"]
                                policy["id"] = cid
                                policy["name"] = conflicting_name
                                put_resp = requests.put(
                                    f"{RANGER_API}/policy/{cid}",
                                    json=policy,
                                    auth=RANGER_AUTH,
                                    timeout=30,
                                )
                                put_resp.raise_for_status()
                                self._record_written(cid)
                                logger.info(
                                    "Updated conflicting policy id=%s name='%s'",
                                    cid,
                                    conflicting_name,
                                )
                                self.policies_pushed += 1
                                return True
                    # If we could not resolve the conflict, raise
                    post_resp.raise_for_status()
                else:
                    post_resp.raise_for_status()
                new_id = post_resp.json().get("id", "?")
                self._record_written(new_id)
                logger.info("Created Ranger policy id=%s name='%s'", new_id, policy_name)

            self.policies_pushed += 1
            return True

        except requests.RequestException as exc:
            # Log detailed error body for 400 errors
            resp_body = ""
            if hasattr(exc, "response") and exc.response is not None:
                resp_body = exc.response.text[:300]
            logger.error(
                "Failed to push policy '%s' to Ranger: %s | %s",
                policy_name,
                exc,
                resp_body,
            )
            self.policies_failed += 1
            return False

    def push_all(self, policies: list[dict[str, Any]]) -> int:
        """Push a batch of policies. Returns the number successfully pushed.

        Merges policies that share the same resource scope (Ranger requires
        unique resources per policy within a service). Automatically provisions
        any users and groups referenced in policies that do not yet exist in Ranger.

        **Safeguard:** If more than 50% of pushes fail in a single run, aborts
        the remaining pushes to prevent inconsistent state. The caller should
        not save the drift snapshot on abort so the next run re-detects everything.
        """
        merged = self._merge_by_resource(policies)
        self._written_ids = set()
        self._ensure_ranger_principals(merged)
        success = 0
        total = len(merged)
        for i, policy in enumerate(merged):
            if self.push_policy(policy):
                success += 1
            # Check for majority failure — abort early if > 50% have failed
            attempted = i + 1
            failures = attempted - success
            if total > 1 and failures > total / 2:
                logger.error(
                    "EXTRACTION ABORTED: %d/%d failures — possible systemic issue. "
                    "Remaining %d policies not pushed.",
                    failures,
                    total,
                    total - attempted,
                )
                self._aborted = True
                return success
        return success

    def _list_policies(self, service: str) -> list[dict[str, Any]]:
        """Every policy in ``service``, across Ranger's result pages."""
        policies: list[dict[str, Any]] = []
        start = 0
        while True:
            resp = requests.get(
                f"{RANGER_API}/policy",
                params={"serviceName": service, "startIndex": start, "pageSize": RANGER_PAGE_SIZE},
                auth=RANGER_AUTH,
                timeout=30,
            )
            resp.raise_for_status()
            page = resp.json()
            policies.extend(page)
            if len(page) < RANGER_PAGE_SIZE:
                return policies
            start += len(page)

    def reconcile_removed(self, services: set[str] | None = None) -> dict[str, list[str]]:
        """Delete this source's allow policies that this run did not write.

        Upserting alone cannot revoke everything. When a resource's last grant
        disappears at the source, nothing is pushed for that resource, so its old
        allow policy stays in Ranger indefinitely. After a fully successful push,
        every policy this source should have was created or updated, and its
        Ranger id recorded; any other policy labelled ``source:<this source>`` is
        stale. Reconciling by id rather than by name matters: on a resource
        conflict, ``push_policy`` updates the existing policy under its old name.

        Only plain allow policies are deleted; removing a masking, row-filter or
        deny policy would widen access, so those are reported for review.

        Returns ``{"deleted": [...], "needs_review": [...]}`` by policy name.
        """
        label = f"source:{self.source_name}"
        result: dict[str, list[str]] = {"deleted": [], "needs_review": []}
        stale: list[dict[str, Any]] = []
        for service in sorted((services or set()) | {RANGER_SERVICE}):
            stale.extend(
                p
                for p in self._list_policies(service)
                if label in p.get("policyLabels", []) and p.get("id") not in self._written_ids
            )
        for existing in stale:
            if existing.get("policyType", 0) != 0 or existing.get("denyPolicyItems"):
                result["needs_review"].append(existing["name"])
                continue
            requests.delete(
                f"{RANGER_API}/policy/{existing['id']}",
                auth=RANGER_AUTH,
                timeout=30,
            ).raise_for_status()
            result["deleted"].append(existing["name"])
        if result["deleted"] or result["needs_review"]:
            logger.warning(
                "Reconciled %s: deleted %d revoked allow policies; %d removed masking/deny "
                "policies need review: %s",
                self.source_name,
                len(result["deleted"]),
                len(result["needs_review"]),
                result["needs_review"],
            )
        return result

    @staticmethod
    def _resource_key(policy: dict[str, Any]) -> tuple:
        """Return a hashable key for the policy's resource scope + type + priority."""
        resources = policy.get("resources", {})
        parts: list[tuple[str, tuple[str, ...]]] = []
        for rname in sorted(resources):
            vals = tuple(sorted(resources[rname].get("values", [])))
            parts.append((rname, vals))
        return (
            policy.get("service", ""),
            policy.get("policyType", 0),
            policy.get("policyPriority", 0),
            tuple(parts),
        )

    @classmethod
    def _merge_by_resource(cls, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Merge policies that share the same resource scope into one policy.

        For access policies (type 0), merges policyItems and denyPolicyItems.
        For masking policies (type 1), merges dataMaskPolicyItems.
        For row-filter policies (type 2), merges rowFilterPolicyItems.
        """
        grouped: dict[tuple, dict[str, Any]] = {}

        for policy in policies:
            key = cls._resource_key(policy)
            if key not in grouped:
                grouped[key] = copy.deepcopy(policy)  # never mutate the caller's policies
                # Ensure labels are combined
                grouped[key].setdefault("policyLabels", [])
            else:
                existing = grouped[key]
                # Merge policyItems
                for items_key in (
                    "policyItems",
                    "denyPolicyItems",
                    "dataMaskPolicyItems",
                    "rowFilterPolicyItems",
                ):
                    new_items = policy.get(items_key, [])
                    if new_items:
                        existing.setdefault(items_key, [])
                        existing[items_key].extend(new_items)

                # Merge labels (deduplicate)
                new_labels = policy.get("policyLabels", [])
                existing_labels = set(existing.get("policyLabels", []))
                for label in new_labels:
                    if label not in existing_labels:
                        existing["policyLabels"].append(label)
                        existing_labels.add(label)

        # Sort dataMaskPolicyItems: MASK_NONE (exception) items first.
        # Ranger evaluates items in order and takes the first group match.
        # Without this sort, 'public → SHOW_LAST_4' matches before
        # 'risk_investigators → MASK_NONE' since everyone is in 'public'.
        for policy in grouped.values():
            mask_items = policy.get("dataMaskPolicyItems", [])
            if len(mask_items) > 1:
                policy["dataMaskPolicyItems"] = sorted(
                    mask_items,
                    key=lambda item: (
                        0 if item.get("dataMaskInfo", {}).get("dataMaskType") == "MASK_NONE" else 1
                    ),
                )

        return list(grouped.values())

    # ------------------------------------------------------------------
    # Ranger principal provisioning
    # ------------------------------------------------------------------

    def _ensure_ranger_principals(self, policies: list[dict[str, Any]]) -> None:
        """Create users and groups in Ranger if they do not already exist."""
        users: set[str] = set()
        groups: set[str] = set()

        for policy in policies:
            for item_key in (
                "policyItems",
                "denyPolicyItems",
                "dataMaskPolicyItems",
                "rowFilterPolicyItems",
            ):
                for item in policy.get(item_key, []):
                    for u in item.get("users", []):
                        if u and u != "{USER}":
                            users.add(u)
                    for g in item.get("groups", []):
                        if g and g != "public":
                            groups.add(g)

        for group_name in groups:
            self._ensure_ranger_group(group_name)
        for user_name in users:
            self._ensure_ranger_user(user_name)

    def _ensure_ranger_user(self, name: str) -> None:
        """Create a Ranger user if it does not already exist."""
        try:
            resp = requests.get(
                f"{RANGER_BASE_URL}/service/xusers/users/userName/{name}",
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code == 200:
                return  # already exists
        except requests.RequestException as exc:
            logger.debug("Could not check if Ranger user '%s' exists: %s", name, exc)

        user_password = os.getenv("RANGER_USER_DEFAULT_PASSWORD", "")
        if not user_password and _RANGER_HOST != "localhost":
            raise RuntimeError(
                "RANGER_USER_DEFAULT_PASSWORD must be set when RANGER_HOST "
                "is not localhost. Set it in your .env file."
            )

        try:
            payload = {
                "name": name,
                "firstName": name,
                "lastName": "ext",
                "status": 1,
                "isVisible": 1,
                "userRoleList": ["ROLE_USER"],
                "userSource": 0,
                "password": user_password,
            }
            resp = requests.post(
                f"{RANGER_BASE_URL}/service/xusers/secure/users",
                json=payload,
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                logger.info("Created Ranger user: %s", name)
            else:
                logger.debug(
                    "Could not create Ranger user '%s': %s %s",
                    name,
                    resp.status_code,
                    resp.text[:200],
                )
        except requests.RequestException as exc:
            logger.debug("Failed to create Ranger user '%s': %s", name, exc)

    def _ensure_ranger_group(self, name: str) -> None:
        """Create a Ranger group if it does not already exist."""
        try:
            resp = requests.get(
                f"{RANGER_BASE_URL}/service/xusers/groups/groupName/{name}",
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code == 200:
                return  # already exists
        except requests.RequestException as exc:
            logger.debug("Could not check if Ranger group '%s' exists: %s", name, exc)

        try:
            payload = {
                "name": name,
                "description": f"Auto-provisioned by {self.source_name} extractor",
                "groupType": 0,
                "groupSource": 0,
                "isVisible": 1,
            }
            resp = requests.post(
                f"{RANGER_BASE_URL}/service/xusers/secure/groups",
                json=payload,
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                logger.info("Created Ranger group: %s", name)
            else:
                logger.debug(
                    "Could not create Ranger group '%s': %s %s",
                    name,
                    resp.status_code,
                    resp.text[:200],
                )
        except requests.RequestException as exc:
            logger.debug("Failed to create Ranger group '%s': %s", name, exc)

    # ------------------------------------------------------------------
    # Drift detection
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_policy_hash(policy: dict[str, Any]) -> str:
        """Compute a deterministic SHA-256 hash of a policy's stable fields.

        Excludes volatile fields (id, createTime, updateTime, version, guid)
        so that unchanged policies produce the same hash across extractions.

        Args:
            policy: A Ranger policy dict.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        stable_fields = {
            "resources": policy.get("resources", {}),
            "policyItems": policy.get("policyItems", []),
            "denyPolicyItems": policy.get("denyPolicyItems", []),
            "dataMaskPolicyItems": policy.get("dataMaskPolicyItems", []),
            "rowFilterPolicyItems": policy.get("rowFilterPolicyItems", []),
            "policyType": policy.get("policyType", 0),
            "isEnabled": policy.get("isEnabled", True),
        }
        canonical = json.dumps(stable_fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _snapshot_path(self) -> Path:
        """Return the path to this extractor's snapshot file."""
        return _SNAPSHOTS_DIR / f"{self.source_name}_latest.json"

    def _load_snapshot(self) -> dict[str, str]:
        """Load the previous policy snapshot (policy_name -> hash).

        Returns an empty dict if no snapshot exists.

        Returns:
            Dict mapping policy names to their SHA-256 hashes.
        """
        path = self._snapshot_path()
        if not path.exists():
            return {}
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load snapshot %s: %s", path, exc)
            return {}

    def _save_snapshot(self, policies: list[dict[str, Any]]) -> None:
        """Save a policy snapshot (policy_name -> hash) for future drift detection.

        Args:
            policies: List of Ranger policy dicts to snapshot.
        """
        _SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
        snapshot: dict[str, str] = {}
        for policy in policies:
            name = policy.get("name", "")
            if name:
                snapshot[name] = self._compute_policy_hash(policy)
        try:
            with open(self._snapshot_path(), "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, indent=2)
            logger.debug("Saved snapshot with %d policies for %s", len(snapshot), self.source_name)
        except OSError as exc:
            logger.warning("Could not save snapshot for %s: %s", self.source_name, exc)

    def _detect_drift(self, policies: list[dict[str, Any]]) -> dict[str, Any]:
        """Compare current policies against the previous snapshot.

        Returns a drift summary with added, removed, modified, and security_alerts.

        Args:
            policies: Current extraction's policy list.

        Returns:
            Dict with keys: added, removed, modified, security_alerts.
        """
        previous = self._load_snapshot()
        current: dict[str, str] = {}
        current_by_name: dict[str, dict[str, Any]] = {}
        for policy in policies:
            name = policy.get("name", "")
            if name:
                current[name] = self._compute_policy_hash(policy)
                current_by_name[name] = policy

        prev_names = set(previous.keys())
        curr_names = set(current.keys())

        added = sorted(curr_names - prev_names)
        removed = sorted(prev_names - curr_names)
        modified = sorted(
            name for name in (curr_names & prev_names) if current[name] != previous[name]
        )

        # Security alerts for high-risk drift
        security_alerts: list[str] = []
        for name in removed:
            if "mask" in name.lower():
                alert = f"DRIFT ALERT: masking removed from {name}"
                security_alerts.append(alert)
                logger.warning(alert)
            if "deny" in name.lower():
                alert = f"DRIFT ALERT: deny removed from {name}"
                security_alerts.append(alert)
                logger.warning(alert)

        for name in modified:
            policy = current_by_name.get(name, {})
            # Check if access was widened (more policyItems than before)
            prev_hash = previous.get(name, "")
            if prev_hash and prev_hash != current.get(name, ""):
                alert = f"DRIFT ALERT: access widened on {name}"
                security_alerts.append(alert)
                logger.warning(alert)

        drift = {
            "added": added,
            "removed": removed,
            "modified": modified,
            "security_alerts": security_alerts,
            "total_previous": len(previous),
            "total_current": len(current),
        }

        if added or removed or modified:
            logger.info(
                "Drift detected for %s: +%d added, -%d removed, ~%d modified, %d alerts",
                self.source_name,
                len(added),
                len(removed),
                len(modified),
                len(security_alerts),
            )
        else:
            logger.info("No drift detected for %s", self.source_name)

        return drift

    # ------------------------------------------------------------------
    # Policy construction helpers
    # ------------------------------------------------------------------

    def make_access_policy(
        self,
        *,
        name: str,
        database: str,
        table: str,
        columns: list[str] | None = None,
        users: list[str] | None = None,
        groups: list[str] | None = None,
        accesses: list[dict[str, Any]] | None = None,
        extra_labels: list[str] | None = None,
        service: str | None = None,
        deny_items: list[dict[str, Any]] | None = None,
        schema: str | None = None,
    ) -> dict[str, Any]:
        """Build a Ranger access policy (policyType 0).

        Uses Trino resource format: catalog/schema/table/column.
        The ``database`` parameter maps to the Trino catalog name.
        The ``schema`` parameter defaults to "default" if not provided.
        """
        if accesses is None:
            accesses = [{"type": "select", "isAllowed": True}]

        policy: dict[str, Any] = {
            "policyType": 0,
            "service": service or RANGER_SERVICE,
            "name": name,
            "isEnabled": True,
            "resources": {
                "catalog": {"values": [database]},
                "schema": {"values": [schema or "default"]},
                "table": {"values": [table]},
                "column": {"values": columns or ["*"]},
            },
            "policyItems": [
                {
                    "users": users or [],
                    "groups": groups or [],
                    "accesses": accesses,
                }
            ],
            "policyLabels": self._base_labels(extra_labels),
        }
        if deny_items:
            policy["denyPolicyItems"] = deny_items
        return policy

    def make_masking_policy(
        self,
        *,
        name: str,
        database: str,
        table: str,
        column: str,
        mask_type: str = "MASK_HASH",
        users: list[str] | None = None,
        groups: list[str] | None = None,
        extra_labels: list[str] | None = None,
        service: str | None = None,
        schema: str | None = None,
        policy_priority: int = 0,
    ) -> dict[str, Any]:
        """Build a Ranger masking policy (policyType 1).

        Uses Trino resource format: catalog/schema/table/column.

        Args:
            policy_priority: 0 = normal, 1 = override. Override policies take
                precedence. Use priority=1 for MASK_NONE exception policies so
                they override the default mask (Ranger evaluates the most
                restrictive mask within same-priority policies).
        """
        return {
            "policyType": 1,
            "policyPriority": policy_priority,
            "service": service or RANGER_SERVICE,
            "name": name,
            "isEnabled": True,
            "resources": {
                "catalog": {"values": [database]},
                "schema": {"values": [schema or "default"]},
                "table": {"values": [table]},
                "column": {"values": [column]},
            },
            "dataMaskPolicyItems": [
                {
                    "users": users or [],
                    "groups": groups or [],
                    "dataMaskInfo": {"dataMaskType": mask_type},
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ],
            "policyLabels": self._base_labels(extra_labels),
        }

    def make_row_filter_policy(
        self,
        *,
        name: str,
        database: str,
        table: str,
        filter_expr: str,
        users: list[str] | None = None,
        groups: list[str] | None = None,
        extra_labels: list[str] | None = None,
        service: str | None = None,
        schema: str | None = None,
    ) -> dict[str, Any]:
        """Build a Ranger row-filter policy (policyType 2).

        Uses Trino resource format: catalog/schema/table.
        """
        return {
            "policyType": 2,
            "service": service or RANGER_SERVICE,
            "name": name,
            "isEnabled": True,
            "resources": {
                "catalog": {"values": [database]},
                "schema": {"values": [schema or "default"]},
                "table": {"values": [table]},
            },
            "rowFilterPolicyItems": [
                {
                    "users": users or [],
                    "groups": groups or [],
                    "rowFilterInfo": {"filterExpr": filter_expr},
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ],
            "policyLabels": self._base_labels(extra_labels),
        }

    def make_tag_based_masking_policy(
        self,
        *,
        name: str,
        tag: str,
        column: str,
        mask_type: str = "MASK_HASH",
        users: list[str] | None = None,
        groups: list[str] | None = None,
        extra_labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build a Ranger tag-based masking policy.

        Tag-based policies evaluate before resource-based policies and apply
        to any resource tagged with the specified classification. Uses wildcard
        resources since the tag association determines scope.

        Args:
            name: Policy name.
            tag: Tag name (e.g. "pii", "sensitive").
            column: Column name to mask.
            mask_type: Ranger mask type (MASK_HASH, MASK_NONE, etc.).
            users: Users to apply masking for.
            groups: Groups to apply masking for.
            extra_labels: Additional policy labels.

        Returns:
            Ranger policy dict for tag-based masking.
        """
        labels = self._base_labels(extra_labels)
        labels.append(f"tag:{tag}")
        labels.append("classification_driven")

        return {
            "policyType": 1,
            "service": RANGER_SERVICE,
            "name": name,
            "isEnabled": True,
            "resources": {
                "catalog": {"values": ["*"]},
                "schema": {"values": ["*"]},
                "table": {"values": ["*"]},
                "column": {"values": [column]},
            },
            "dataMaskPolicyItems": [
                {
                    "users": users or [],
                    "groups": groups or [],
                    "dataMaskInfo": {"dataMaskType": mask_type},
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ],
            "policyLabels": labels,
        }

    def _base_labels(self, extra: list[str] | None = None) -> list[str]:
        """Return the standard provenance labels plus any extras."""
        labels = [
            f"source:{self.source_name}",
            f"extraction_ts:{self._extraction_ts}",
        ]
        if extra:
            labels.extend(extra)
        return labels

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def extract_and_push(self) -> dict[str, Any]:
        """Full pipeline: extract from source, detect drift, push to Ranger.

        Drift detection runs before pushing. If push aborts due to majority
        failure, the snapshot is NOT saved so the next run re-detects everything.

        Returns:
            Summary dict with extraction stats and drift info.
        """
        logger.info("Starting extraction: %s", self.source_name)
        try:
            policies = self.extract_policies()
        except Exception as exc:
            logger.error("Extraction failed for %s: %s", self.source_name, exc)
            return {
                "source": self.source_name,
                "status": "error",
                "error": str(exc),
                "policies_extracted": 0,
                "policies_pushed": 0,
            }

        logger.info("Extracted %d policies from %s", len(policies), self.source_name)

        # Drift detection
        drift = self._detect_drift(policies)

        self.push_all(policies)

        # Remove what the source stopped granting. Only after a fully successful
        # push: a failed write would otherwise look stale and be deleted. Also
        # skipped when the extraction came back empty, which more likely means an
        # outage than a platform with no grants at all.
        reconciled: dict[str, list[str]] = {"deleted": [], "needs_review": []}
        if policies and not self._aborted and self.policies_failed == 0:
            services = {p.get("service", RANGER_SERVICE) for p in policies}
            reconciled = self.reconcile_removed(services)

        # Only save snapshot if push was not aborted
        if not self._aborted:
            self._save_snapshot(policies)
        else:
            logger.warning(
                "Snapshot NOT saved for %s — push was aborted due to majority failure",
                self.source_name,
            )

        summary: dict[str, Any] = {
            "source": self.source_name,
            "status": "aborted" if self._aborted else "complete",
            "policies_extracted": len(policies),
            "policies_pushed": self.policies_pushed,
            "policies_failed": self.policies_failed,
            "policies_deleted": reconciled["deleted"],
            "removed_policies_needing_review": reconciled["needs_review"],
            "extraction_ts": self._extraction_ts,
            "drift": drift,
        }
        logger.info("Extraction complete: %s", summary)
        return summary

    # ------------------------------------------------------------------
    # Contract output
    # ------------------------------------------------------------------

    @staticmethod
    def write_contract(summaries: list[dict[str, Any]]) -> None:
        """Write the consolidated contract file for all extractors."""
        CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)
        total_extracted = sum(s.get("policies_extracted", 0) for s in summaries)
        total_pushed = sum(s.get("policies_pushed", 0) for s in summaries)

        contract = {
            "agent": "policy-extraction",
            "status": "complete",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "details": {
                "total_policies_extracted": total_extracted,
                "total_policies_pushed": total_pushed,
                "per_platform": {
                    s["source"]: {
                        "status": s.get("status", "unknown"),
                        "policies_extracted": s.get("policies_extracted", 0),
                        "policies_pushed": s.get("policies_pushed", 0),
                        "policies_failed": s.get("policies_failed", 0),
                    }
                    for s in summaries
                },
            },
        }

        path = CONTRACTS_DIR / "policies-extracted.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(contract, fh, indent=2)
        logger.info("Contract written to %s", path)
