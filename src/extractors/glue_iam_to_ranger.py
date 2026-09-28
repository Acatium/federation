"""Glue/IAM -> Ranger policy extractor.

Two extraction methods:
1. Glue resource policies — reads ``glue:GetResourcePolicies`` to find
   IAM-style allow/deny statements on Glue databases and tables.
2. IAM policy simulation — uses ``iam:SimulatePrincipalPolicy`` to test
   known IAM roles against Glue table ARNs and captures effective permissions.

Labels: source:glue_iam, governance_tier:platform_native,
        translation_gap:iam_condition_keys_not_mapped
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from src.extractors.base import (
    BaseExtractor,
    DEMO_DATABASE,
    DEMO_TABLES,
)
from src.utils.sql_safety import validate_iam_role_arn

load_dotenv()

logger = logging.getLogger(__name__)

# Glue action -> Ranger access type mapping
# Glue IAM action -> the Ranger access types it makes possible. For a Lake
# Formation-governed table IAM is a necessary condition, not the grant: a read
# needs glue:GetTable here AND SELECT in Lake Formation. So GetTable enables
# select (and show); listing and describe calls enable only show; partition calls
# are needed for reads but grant nothing alone. Unlisted actions grant nothing.
GLUE_ACTION_MAP: dict[str, tuple[str, ...]] = {
    "glue:GetTable": ("select", "show"),
    "glue:GetTables": ("show",),
    "glue:GetDatabase": ("show",),
    "glue:GetDatabases": ("show",),
    "glue:SearchTables": ("show",),
    "glue:GetPartition": (),
    "glue:GetPartitions": (),
    "glue:BatchGetPartition": (),
    "glue:CreateTable": ("create",),
    "glue:CreateDatabase": ("create",),
    "glue:UpdateTable": ("alter",),
    "glue:UpdateDatabase": ("alter",),
    "glue:DeleteTable": ("drop",),
    "glue:DeleteDatabase": ("drop",),
    "glue:*": ("all",),
}

# IAM ARN patterns
_IAM_ROLE_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@\-/]+$")
_IAM_USER_RE = re.compile(r"^arn:aws:iam::\d{12}:user/[\w+=,.@\-/]+$")


def _arn_to_ranger_principal(arn: str) -> tuple[list[str], list[str]]:
    """Convert an IAM ARN to Ranger (users, groups) lists.

    Roles map to Ranger groups; IAM users map to Ranger users.

    Args:
        arn: An IAM ARN string.

    Returns:
        Tuple of (users_list, groups_list).

    Raises:
        ValueError: If the ARN is malformed.
    """
    short_name = arn.split("/")[-1] if "/" in arn else arn
    if _IAM_ROLE_RE.match(arn):
        return [], [short_name]
    if _IAM_USER_RE.match(arn):
        return [short_name], []
    # Fallback: treat as user
    if "arn:" in arn:
        raise ValueError(f"Unrecognized IAM ARN format: {arn!r}")
    return [short_name], []


def _map_glue_actions(actions: list[str]) -> list[str]:
    """Map Glue IAM actions to the Ranger access types they make possible.

    Args:
        actions: IAM action strings (e.g., ["glue:GetTable"]).

    Returns:
        Sorted, de-duplicated Ranger access types; empty if none apply.
    """
    return sorted({t for action in actions for t in GLUE_ACTION_MAP.get(action, ())})


class GlueIamExtractor(BaseExtractor):
    """Extract Glue resource policies and IAM permissions as Ranger policies."""

    def __init__(self) -> None:
        super().__init__(source_name="glue_iam")
        self.region: str = os.getenv("AWS_REGION", "us-east-2")
        self.account_id: str = os.getenv("AWS_ACCOUNT_ID", "")
        self.catalog_id: str = os.getenv("GLUE_CATALOG_ID", os.getenv("AWS_ACCOUNT_ID", ""))
        self.database: str = os.getenv("GLUE_DATABASE", DEMO_DATABASE)
        self.glue_client = boto3.client("glue", region_name=self.region)
        self.iam_client = boto3.client("iam", region_name=self.region)

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_policies(self) -> list[dict[str, Any]]:
        """Pull Glue resource policies and IAM simulations, return Ranger policies."""
        policies: list[dict[str, Any]] = []

        # Method 1: Glue resource policies
        resource_policies = self._extract_glue_resource_policies()
        policies.extend(resource_policies)

        # Method 2: IAM policy simulation for known roles
        iam_policies = self._extract_iam_glue_permissions()
        policies.extend(iam_policies)

        logger.info(
            "Extracted %d Glue/IAM policies (%d resource, %d IAM sim)",
            len(policies),
            len(resource_policies),
            len(iam_policies),
        )
        return policies

    # ------------------------------------------------------------------
    # Glue resource policies
    # ------------------------------------------------------------------

    def _extract_glue_resource_policies(self) -> list[dict[str, Any]]:
        """Extract Glue resource policies via glue:GetResourcePolicies.

        Parses IAM-style Statements and maps Glue actions to Ranger accesses.

        Returns:
            List of Ranger policy dicts.
        """
        policies: list[dict[str, Any]] = []
        try:
            paginator = self.glue_client.get_paginator("get_resource_policies")
            for page in paginator.paginate():
                for rp in page.get("GetResourcePoliciesResponseList", []):
                    policy_json = rp.get("PolicyInJson", "{}")
                    try:
                        policy_doc = json.loads(policy_json)
                    except json.JSONDecodeError:
                        logger.warning("Malformed Glue resource policy JSON — skipping")
                        continue
                    for statement in policy_doc.get("Statement", []):
                        ranger_policies = self._parse_resource_statement(statement)
                        policies.extend(ranger_policies)
        except ClientError as exc:
            logger.warning("Could not fetch Glue resource policies: %s", exc)
        return policies

    def _parse_resource_statement(self, statement: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse a single IAM policy statement into Ranger policies.

        Args:
            statement: An IAM Statement dict with Effect, Principal, Action, Resource.

        Returns:
            List of Ranger policy dicts.
        """
        effect = statement.get("Effect", "Allow")
        principals_raw = statement.get("Principal", {})
        actions_raw = statement.get("Action", [])
        resources_raw = statement.get("Resource", [])

        # Normalize to lists
        if isinstance(actions_raw, str):
            actions_raw = [actions_raw]
        if isinstance(resources_raw, str):
            resources_raw = [resources_raw]

        # Extract principal ARNs
        principal_arns: list[str] = []
        if isinstance(principals_raw, str):
            principal_arns = [principals_raw]
        elif isinstance(principals_raw, dict):
            for key in ("AWS", "Service"):
                val = principals_raw.get(key, [])
                if isinstance(val, str):
                    principal_arns.append(val)
                elif isinstance(val, list):
                    principal_arns.extend(val)

        # Map actions to Ranger accesses; a statement that enables none is skipped
        ranger_accesses = [{"type": t, "isAllowed": True} for t in _map_glue_actions(actions_raw)]
        if not ranger_accesses:
            return []

        policies: list[dict[str, Any]] = []
        for arn in principal_arns:
            # Determine tables from resource ARNs
            tables = self._extract_tables_from_arns(resources_raw)

            for table in tables or DEMO_TABLES:
                try:
                    users, groups = _arn_to_ranger_principal(arn)
                except ValueError as exc:
                    logger.warning("Skipping invalid ARN %s: %s", arn, exc)
                    continue

                short_name = arn.split("/")[-1] if "/" in arn else arn
                policy_name = f"glue_iam_{self.database}_{table}_{short_name}"

                extra_labels = [
                    "governance_tier:platform_native",
                    "translation_gap:iam_condition_keys_not_mapped",
                    f"iam_principal:{arn}",
                ]

                if effect == "Allow":
                    policy = self.make_access_policy(
                        name=policy_name,
                        database="hive",
                        table=table,
                        users=users,
                        groups=groups,
                        accesses=ranger_accesses,
                        extra_labels=extra_labels,
                        schema=self.database,
                    )
                else:
                    # Deny effect -> denyPolicyItems
                    policy = self.make_access_policy(
                        name=policy_name,
                        database="hive",
                        table=table,
                        extra_labels=extra_labels,
                        schema=self.database,
                        deny_items=[
                            {
                                "users": users,
                                "groups": groups,
                                "accesses": ranger_accesses,
                            }
                        ],
                    )
                    policy["policyItems"] = []

                policies.append(policy)

        return policies

    def _extract_tables_from_arns(self, arns: list[str]) -> list[str]:
        """Extract table names from Glue resource ARNs.

        Args:
            arns: List of ARN strings.

        Returns:
            List of table names found, or empty list if none matched.
        """
        tables: list[str] = []
        for arn in arns:
            # Pattern: arn:aws:glue:region:account:table/database/table_name
            match = re.match(r"arn:aws:glue:[^:]+:\d+:table/[^/]+/(.+)$", arn)
            if match:
                tables.append(match.group(1))
        return tables

    # ------------------------------------------------------------------
    # IAM simulation
    # ------------------------------------------------------------------

    def _extract_iam_glue_permissions(self) -> list[dict[str, Any]]:
        """Simulate IAM policy evaluation for known roles against Glue ARNs.

        Uses iam:SimulatePrincipalPolicy to test Glue actions.

        Returns:
            List of Ranger policy dicts for allowed simulated actions.
        """
        if not self.account_id:
            logger.info("AWS_ACCOUNT_ID not set — skipping IAM simulation")
            return []

        spectrum_role = os.getenv("SPECTRUM_ROLE_ARN", "")
        if not spectrum_role:
            logger.info("SPECTRUM_ROLE_ARN not set — skipping IAM simulation")
            return []

        try:
            validate_iam_role_arn(spectrum_role)
        except ValueError as exc:
            logger.warning("Invalid SPECTRUM_ROLE_ARN: %s", exc)
            return []

        policies: list[dict[str, Any]] = []
        actions_to_test = [
            "glue:GetTable",
            "glue:GetTables",
            "glue:GetDatabase",
            "glue:CreateTable",
            "glue:DeleteTable",
        ]

        for table in DEMO_TABLES:
            table_arn = (
                f"arn:aws:glue:{self.region}:{self.account_id}:table/{self.database}/{table}"
            )
            try:
                resp = self.iam_client.simulate_principal_policy(
                    PolicySourceArn=spectrum_role,
                    ActionNames=actions_to_test,
                    ResourceArns=[table_arn],
                )
            except ClientError as exc:
                logger.warning(
                    "IAM simulation failed for role %s on %s: %s",
                    spectrum_role,
                    table,
                    exc,
                )
                continue

            allowed_actions = [
                result.get("EvalActionName", "")
                for result in resp.get("EvaluationResults", [])
                if result.get("EvalDecision") == "allowed"
            ]
            allowed_accesses = [{"type": t, "isAllowed": True} for t in _map_glue_actions(allowed_actions)]

            if allowed_accesses:
                role_name = spectrum_role.split("/")[-1]
                policy_name = f"glue_iam_sim_{self.database}_{table}_{role_name}"
                policy = self.make_access_policy(
                    name=policy_name,
                    database="hive",
                    table=table,
                    groups=[role_name],
                    accesses=allowed_accesses,
                    extra_labels=[
                        "governance_tier:platform_native",
                        "translation_gap:iam_condition_keys_not_mapped",
                        f"iam_role:{spectrum_role}",
                        "extraction_method:iam_simulation",
                    ],
                    schema=self.database,
                )
                policies.append(policy)

        return policies


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = GlueIamExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Glue/IAM extractor result: %s", result)
