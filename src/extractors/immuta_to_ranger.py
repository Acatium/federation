"""Immuta -> Ranger policy extractor (mock-compatible).

Connects to the Immuta REST API (real or mock) at IMMUTA_BASE_URL, reads
policies, permissions, and data source registrations, and pushes normalised
Ranger policies via the Ranger REST API.

Lossy translations are documented in policy labels:
- Purpose gates are lost (Ranger grants by role, not active purpose)
- Dynamic ABAC user-attribute bindings are flattened to static per-group filters
- Time-bounded access has no native Ranger equivalent (tracked via labels)

Labels: source:immuta, immuta_mode:mock|live, governance_tier:immuta_fgac
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests as http_requests
from dotenv import load_dotenv

from src.extractors.base import BaseExtractor, DEMO_DATABASE
from src.utils.sql_safety import validate_row_filter_expr

load_dotenv()

logger = logging.getLogger(__name__)

# SIMULATION NOTE: Default URL points to the mock server (src.mocks.immuta_mock).
# Set IMMUTA_BASE_URL in .env to connect to a real Immuta instance.
DEFAULT_IMMUTA_URL: str = "http://localhost:8089"

# Immuta mask type -> Ranger mask type mapping
IMMUTA_MASK_MAP: dict[str, str] = {
    "SHOW_LAST_4": "MASK_SHOW_LAST_4",
    "HASH_SHA256": "MASK_HASH",
    "HASH": "MASK_HASH",
    "NULLIFY": "MASK_NULL",
    "REDACT": "MASK",
    "MASK": "MASK",
}

# Known region -> group mappings for flattening dynamic ABAC
REGION_GROUP_MAP: dict[str, str] = {
    "NA": "na_analysts",
    "EMEA": "emea_traders",
    "APAC": "apac_analysts",
}


class ImmutaExtractor(BaseExtractor):
    """Extract Immuta policies and convert to Ranger format.

    Works identically against mock or real Immuta — the only difference
    is the IMMUTA_BASE_URL value.
    """

    def __init__(self) -> None:
        super().__init__(source_name="immuta")
        self.base_url: str = (
            os.getenv("IMMUTA_BASE_URL", "") or DEFAULT_IMMUTA_URL
        ).rstrip("/")
        self.api_key: str = os.getenv("IMMUTA_API_KEY", "")
        self._session = http_requests.Session()
        if self.api_key:
            self._session.headers.update(
                {"Authorization": f"Bearer {self.api_key}"}
            )
        self.immuta_mode: str = "unknown"

    # ------------------------------------------------------------------
    # REST helpers
    # ------------------------------------------------------------------

    def _api_get(self, path: str) -> Any:
        """Make an authenticated GET to the Immuta API."""
        url = f"{self.base_url}{path}"
        resp = self._session.get(url, timeout=30)
        resp.raise_for_status()
        # Detect mock vs live from response header
        mode = resp.headers.get("X-Immuta-Mode", "")
        if mode:
            self.immuta_mode = mode
        return resp.json()

    def _detect_mode(self) -> str:
        """Detect whether we are talking to mock or real Immuta."""
        try:
            data = self._api_get("/health")
            mode = data.get("mode", "live")
            self.immuta_mode = mode
            logger.info("Immuta mode detected: %s", mode)
            return mode
        except http_requests.RequestException:
            # If health check fails, try the policy endpoint to detect
            logger.info(
                "Health endpoint unavailable; will detect mode from responses"
            )
            return "unknown"

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_policies(self) -> list[dict[str, Any]]:
        """Pull Immuta policies and convert to Ranger format."""
        self._detect_mode()

        raw_policies = self._fetch_policies()
        raw_permissions = self._fetch_permissions()
        raw_datasources = self._fetch_datasources()

        logger.info(
            "Fetched from Immuta (%s): %d policies, %d permissions, %d datasources",
            self.immuta_mode,
            len(raw_policies),
            len(raw_permissions),
            len(raw_datasources),
        )

        # Collect all known groups from permissions data.  Used by
        # _convert_masking_action to target specific groups rather than
        # the Ranger 'public' catch-all (which cannot be overridden for
        # exception groups in the Trino Ranger plugin).
        self._known_groups: set[str] = set()
        for perm in raw_permissions:
            group = perm.get("group", "")
            if group:
                self._known_groups.add(group)
        # Also collect groups from subscription/deny actions in policies
        for pol in raw_policies:
            for action in pol.get("actions", []):
                g = action.get("group", "")
                if g:
                    self._known_groups.add(g)
        logger.info("Known Immuta groups: %s", sorted(self._known_groups))

        ranger_policies: list[dict[str, Any]] = []

        # Convert each Immuta policy into one or more Ranger policies
        for policy in raw_policies:
            ranger_policies.extend(self._convert_policy(policy))

        # Convert permission grants into access policies
        ranger_policies.extend(
            self._convert_permissions(raw_permissions, raw_datasources)
        )

        return ranger_policies

    # ------------------------------------------------------------------
    # Fetch data from Immuta
    # ------------------------------------------------------------------

    def _fetch_policies(self) -> list[dict[str, Any]]:
        """Fetch all policies from Immuta."""
        try:
            data = self._api_get("/policy")
            if isinstance(data, list):
                return data
            return data.get("policies", data.get("data", []))
        except http_requests.RequestException as exc:
            logger.error("Failed to fetch Immuta policies: %s", exc)
            return []

    def _fetch_permissions(self) -> list[dict[str, Any]]:
        """Fetch permission grants from Immuta."""
        try:
            data = self._api_get("/permissions")
            if isinstance(data, list):
                return data
            return data.get("permissions", data.get("data", []))
        except http_requests.RequestException as exc:
            logger.error("Failed to fetch Immuta permissions: %s", exc)
            return []

    def _fetch_datasources(self) -> list[dict[str, Any]]:
        """Fetch data source registrations from Immuta."""
        try:
            data = self._api_get("/dataSource")
            if isinstance(data, list):
                return data
            return data.get("dataSources", data.get("data", []))
        except http_requests.RequestException as exc:
            logger.error("Failed to fetch Immuta data sources: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Policy conversion
    # ------------------------------------------------------------------

    def _convert_policy(
        self, policy: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Convert one Immuta policy into one or more Ranger policies.

        Different Immuta policy types map to different Ranger policy types:
        - masking -> policyType 1 (one per column per exception group)
        - row_filter -> policyType 2 (static expansion of dynamic ABAC)
        - subscription -> policyType 0 (access grant or deny)
        """
        policy_type = policy.get("type", "")
        policy_id = policy.get("id", "unknown")
        policy_name = policy.get("name", "unnamed")
        purpose = policy.get("purpose", "unspecified")
        actions = policy.get("actions", [])
        data_sources = policy.get("dataSources", [])

        ranger_policies: list[dict[str, Any]] = []

        for action in actions:
            action_type = action.get("type", "")

            if action_type == "masking":
                ranger_policies.extend(
                    self._convert_masking_action(
                        action, policy_id, purpose, data_sources
                    )
                )
            elif action_type == "row_filter":
                ranger_policies.extend(
                    self._convert_row_filter_action(
                        action, policy_id, purpose, data_sources
                    )
                )
            elif action_type == "subscription":
                ranger_policies.extend(
                    self._convert_subscription_action(
                        action, policy_id, policy_name, purpose, data_sources
                    )
                )
            elif action_type == "deny":
                ranger_policies.extend(
                    self._convert_deny_action(
                        action, policy_id, policy_name, purpose, data_sources
                    )
                )
            else:
                logger.warning(
                    "Unknown Immuta action type '%s' in policy '%s'",
                    action_type,
                    policy_id,
                )

        return ranger_policies

    def _convert_masking_action(
        self,
        action: dict[str, Any],
        policy_id: str,
        purpose: str,
        data_sources: list[str],
    ) -> list[dict[str, Any]]:
        """Convert Immuta masking rules to Ranger masking policies (policyType 1).

        One Ranger policy per (column, data_source) pair. Exception groups get
        excluded from the masking rule.
        """
        policies: list[dict[str, Any]] = []
        rules = action.get("rules", [])

        for rule in rules:
            column = rule.get("column", "unknown")
            mask_type_immuta = rule.get("maskType", "HASH_SHA256")
            ranger_mask = IMMUTA_MASK_MAP.get(
                mask_type_immuta, "MASK_HASH"
            )
            exceptions = rule.get("exceptions", [])
            exception_groups = [
                e.get("group", "") for e in exceptions if e.get("group")
            ]

            for ds in data_sources:
                catalog, schema_name, table = self._parse_datasource(ds)

                safe_col = column.replace(" ", "_").lower()
                safe_ds = ds.replace(".", "_").replace(" ", "_").lower()
                name = f"immuta_mask_{safe_ds}_{safe_col}_{policy_id}"

                extra_labels = [
                    "governance_tier:immuta_fgac",
                    f"immuta_mode:{self.immuta_mode}",
                    f"immuta_policy_id:{policy_id}",
                    f"immuta_purpose:{purpose}",
                    "translation_note:purpose_gate_lost",
                ]

                # Masking applies to everyone EXCEPT the exception groups.
                # The Trino 479 Ranger plugin does not support policyPriority
                # for masking evaluation, so we cannot use a 'public' mask +
                # MASK_NONE override.  Instead, we target ONLY the groups
                # that should see masked data (known_groups - exception_groups).
                # Groups not listed simply see raw data — no mask is applied.
                known = getattr(self, "_known_groups", set())
                if known and exception_groups:
                    mask_groups = sorted(known - set(exception_groups))
                else:
                    mask_groups = ["public"]

                if exception_groups:
                    extra_labels.append(
                        f"immuta_exception_groups:{','.join(exception_groups)}"
                    )

                policy = self.make_masking_policy(
                    name=name,
                    database=catalog,
                    table=table,
                    column=column,
                    mask_type=ranger_mask,
                    groups=mask_groups,
                    extra_labels=extra_labels,
                    schema=schema_name,
                )
                policies.append(policy)

        return policies

    def _convert_row_filter_action(
        self,
        action: dict[str, Any],
        policy_id: str,
        purpose: str,
        data_sources: list[str],
    ) -> list[dict[str, Any]]:
        """Convert Immuta row filter to Ranger row-filter policies (policyType 2).

        Dynamic ABAC bindings like ``${user.region}`` must be expanded to
        concrete static filters per known region/group mapping.
        This is the canonical lossy-translation example.
        """
        policies: list[dict[str, Any]] = []
        filter_expr = action.get("filterExpression", "true")
        try:
            validate_row_filter_expr(filter_expr)
        except ValueError as exc:
            logger.warning(
                "Skipping unsafe Immuta row filter for policy %s: %s",
                policy_id, exc,
            )
            return policies
        exempt_groups = action.get("exemptGroups", [])

        for ds in data_sources:
            catalog, schema_name, table = self._parse_datasource(ds)

            # Check if the filter contains dynamic user-attribute bindings
            # Support both ${user.region} and ${user.jurisdiction} patterns
            has_dynamic = (
                "${user.region}" in filter_expr
                or "${user.jurisdiction}" in filter_expr
            )
            if has_dynamic:
                # Expand to one policy per known region
                for region_value, group_name in REGION_GROUP_MAP.items():
                    # Replace placeholders with region values.
                    # Templates typically include quotes: jurisdiction = '${user.jurisdiction}'
                    # so we don't add quotes around the value.
                    static_filter = filter_expr.replace(
                        "'${user.region}'", f"'{region_value}'"
                    ).replace(
                        "'${user.jurisdiction}'", f"'{region_value}'"
                    ).replace(
                        "${user.region}", region_value
                    ).replace(
                        "${user.jurisdiction}", region_value
                    )
                    safe_ds = ds.replace(".", "_").replace(" ", "_").lower()
                    name = (
                        f"immuta_rowfilter_{safe_ds}_{group_name}_{policy_id}"
                    )

                    extra_labels = [
                        "governance_tier:immuta_fgac",
                        f"immuta_mode:{self.immuta_mode}",
                        f"immuta_policy_id:{policy_id}",
                        f"immuta_purpose:{purpose}",
                        "translation_note:dynamic_abac_flattened_to_static",
                        f"original_filter:{filter_expr}",
                        f"expanded_region:{region_value}",
                    ]

                    policy = self.make_row_filter_policy(
                        name=name,
                        database=catalog,
                        table=table,
                        filter_expr=static_filter,
                        groups=[group_name],
                        extra_labels=extra_labels,
                        schema=schema_name,
                    )
                    policies.append(policy)

                # Exempt groups get unfiltered access
                for group in exempt_groups:
                    safe_ds = ds.replace(".", "_").replace(" ", "_").lower()
                    exempt_name = (
                        f"immuta_rowfilter_exempt_{safe_ds}_{group}_{policy_id}"
                    )

                    extra_labels = [
                        "governance_tier:immuta_fgac",
                        f"immuta_mode:{self.immuta_mode}",
                        f"immuta_policy_id:{policy_id}",
                        f"immuta_purpose:{purpose}",
                        "translation_note:exempt_group_gets_unfiltered_access",
                        f"immuta_exempt_group:{group}",
                    ]

                    policy = self.make_row_filter_policy(
                        name=exempt_name,
                        database=catalog,
                        table=table,
                        filter_expr="true",
                        groups=[group],
                        extra_labels=extra_labels,
                        schema=schema_name,
                    )
                    policies.append(policy)
            else:
                # Static filter — translates directly
                safe_ds = ds.replace(".", "_").replace(" ", "_").lower()
                name = f"immuta_rowfilter_{safe_ds}_{policy_id}"

                extra_labels = [
                    "governance_tier:immuta_fgac",
                    f"immuta_mode:{self.immuta_mode}",
                    f"immuta_policy_id:{policy_id}",
                    f"immuta_purpose:{purpose}",
                    f"original_filter:{filter_expr}",
                ]

                policy = self.make_row_filter_policy(
                    name=name,
                    database=catalog,
                    table=table,
                    filter_expr=filter_expr,
                    groups=["public"],
                    extra_labels=extra_labels,
                    schema=schema_name,
                )
                policies.append(policy)

        return policies

    def _convert_subscription_action(
        self,
        action: dict[str, Any],
        policy_id: str,
        policy_name: str,
        purpose: str,
        data_sources: list[str],
    ) -> list[dict[str, Any]]:
        """Convert Immuta subscription to Ranger access policy (policyType 0).

        Purpose gates are lost. Time-bounded access is recorded in labels
        for a sync job to revoke later.
        """
        policies: list[dict[str, Any]] = []
        group = action.get("group", "")
        access_level = action.get("accessLevel", "SELECT")
        masking_mode = action.get("masking", "none")
        expiry = action.get("expiry", "")

        for ds in data_sources:
            catalog, schema_name, table = self._parse_datasource(ds)
            safe_ds = ds.replace(".", "_").replace(" ", "_").lower()
            safe_group = group.replace(" ", "_").lower()
            name = f"immuta_sub_{safe_ds}_{safe_group}_{policy_id}"

            extra_labels = [
                "governance_tier:immuta_fgac",
                f"immuta_mode:{self.immuta_mode}",
                f"immuta_policy_id:{policy_id}",
                f"immuta_purpose:{purpose}",
                "translation_note:purpose_gate_lost",
            ]
            if expiry:
                extra_labels.append(f"immuta_expiry:{expiry}")
                extra_labels.append(
                    "translation_note:time_expiry_not_enforced_in_ranger"
                )
            if masking_mode == "aggressive":
                extra_labels.append("immuta_masking:aggressive")

            ranger_access = "select" if access_level.upper() == "SELECT" else "all"

            policy = self.make_access_policy(
                name=name,
                database=catalog,
                table=table,
                groups=[group] if group else [],
                accesses=[{"type": ranger_access, "isAllowed": True}],
                extra_labels=extra_labels,
                schema=schema_name,
            )
            policies.append(policy)

        return policies

    def _convert_deny_action(
        self,
        action: dict[str, Any],
        policy_id: str,
        policy_name: str,
        purpose: str,
        data_sources: list[str],
    ) -> list[dict[str, Any]]:
        """Convert Immuta deny to Ranger deny policy (policyType 0 with isAllowed=false)."""
        policies: list[dict[str, Any]] = []
        group = action.get("group", "")
        deny_sources = action.get("dataSources", data_sources)

        for ds in deny_sources:
            catalog, schema_name, table = self._parse_datasource(ds)
            safe_ds = ds.replace(".", "_").replace(" ", "_").lower()
            safe_group = group.replace(" ", "_").lower()
            name = f"immuta_deny_{safe_ds}_{safe_group}_{policy_id}"

            extra_labels = [
                "governance_tier:immuta_fgac",
                f"immuta_mode:{self.immuta_mode}",
                f"immuta_policy_id:{policy_id}",
                f"immuta_purpose:{purpose}",
                "translation_note:purpose_gate_lost",
            ]

            deny_items = [
                {
                    "users": [],
                    "groups": [group] if group else [],
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ]

            policy = self.make_access_policy(
                name=name,
                database=catalog,
                table=table,
                groups=[group] if group else [],
                accesses=[{"type": "select", "isAllowed": True}],
                deny_items=deny_items,
                extra_labels=extra_labels,
                schema=schema_name,
            )
            # Override policyItems to be empty — the deny goes in denyPolicyItems
            policy["policyItems"] = []
            policies.append(policy)

        return policies

    # ------------------------------------------------------------------
    # Permission → access policy conversion
    # ------------------------------------------------------------------

    def _convert_permissions(
        self,
        permissions: list[dict[str, Any]],
        datasources: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Convert Immuta permission grants into Ranger access policies.

        Each permission represents a user's effective access to a data source,
        including their masking status.
        """
        policies: list[dict[str, Any]] = []

        # Build a datasource lookup for governance tier info
        ds_lookup: dict[str, dict[str, Any]] = {}
        for ds in datasources:
            ds_name = ds.get("name", "")
            if ds_name:
                ds_lookup[ds_name] = ds

        for perm in permissions:
            user = perm.get("user", "unknown")
            group = perm.get("group", "")
            access_level = perm.get("accessLevel", "SELECT")
            purpose = perm.get("purpose", "unspecified")
            is_masked = perm.get("masked", True)
            perm_sources = perm.get("dataSources", [])

            for ds_name in perm_sources:
                catalog, schema_name, table = self._parse_datasource(ds_name)
                safe_ds = ds_name.replace(".", "_").replace(" ", "_").lower()
                safe_user = user.replace(" ", "_").replace("@", "_at_").lower()
                name = f"immuta_perm_{safe_ds}_{safe_user}"

                extra_labels = [
                    "governance_tier:immuta_fgac",
                    f"immuta_mode:{self.immuta_mode}",
                    f"immuta_purpose:{purpose}",
                    f"immuta_masked:{is_masked}",
                    "translation_note:permission_grant",
                ]

                ranger_access = (
                    "select" if access_level.upper() == "SELECT" else "all"
                )

                policy = self.make_access_policy(
                    name=name,
                    database=catalog,
                    table=table,
                    users=[user],
                    groups=[group] if group else [],
                    accesses=[{"type": ranger_access, "isAllowed": True}],
                    extra_labels=extra_labels,
                    schema=schema_name,
                )
                policies.append(policy)

        return policies

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_datasource(self, ds: str) -> tuple[str, str, str]:
        """Parse an Immuta data source name into (catalog, schema, table).

        Immuta names like 'redshift.federation.ledger_entries' -> ('redshift', 'federation', 'ledger_entries').
        Four-part names like 'snowflake.FEDERATION_DEMO.PUBLIC.ENTITIES' -> ('snowflake', 'public', 'entities').
        Falls back to ('hive', DEMO_DATABASE, ds) if unparseable.
        """
        parts = ds.split(".")
        if len(parts) >= 4:
            # platform.database.schema.table (e.g. Snowflake fully qualified)
            return parts[0].lower(), parts[2].lower(), parts[3].lower()
        elif len(parts) == 3:
            # platform.schema.table
            return parts[0].lower(), parts[1].lower(), parts[2].lower()
        elif len(parts) == 2:
            return parts[0].lower(), "default", parts[1].lower()
        else:
            return "hive", DEMO_DATABASE, ds.lower()


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = ImmutaExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Immuta extractor result: %s", result)
