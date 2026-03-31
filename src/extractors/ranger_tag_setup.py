"""Ranger tag store setup — create tag definitions and tag-based policies.

Creates tag definitions (pii, sensitive, governance_tier_*) in Ranger's tag
store and pushes tag-based masking/deny policies. Tag-based policies evaluate
BEFORE resource-based policies, providing "write once, enforce everywhere"
classification-driven access control.

Called from deploy/provision.sh after catalogs are registered and before
extractors run.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

_RANGER_HOST: str = os.getenv("RANGER_HOST", "localhost")
_RANGER_PORT: str = os.getenv("RANGER_PORT", "6080")
_RANGER_SCHEME: str = os.getenv("RANGER_SCHEME", "http")

RANGER_BASE_URL: str = f"{_RANGER_SCHEME}://{_RANGER_HOST}:{_RANGER_PORT}"
RANGER_AUTH: tuple[str, str] = (
    os.getenv("RANGER_ADMIN_USER", "admin"),
    os.getenv("RANGER_ADMIN_PASSWORD", ""),
)
RANGER_SERVICE: str = os.getenv("RANGER_SERVICE", "dev_trino")

# Tag definitions to create in Ranger's tag store
TAG_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "pii",
        "description": "Contains personally identifiable information",
        "attributeDefs": [],
    },
    {
        "name": "sensitive",
        "description": "Contains sensitive financial data",
        "attributeDefs": [],
    },
    {
        "name": "governance_tier_platform_native",
        "description": "Tier 1: Platform-native governance",
        "attributeDefs": [],
    },
    {
        "name": "governance_tier_immuta_fgac",
        "description": "Tier 2: Immuta fine-grained access control",
        "attributeDefs": [],
    },
]


class RangerTagSetup:
    """Create Ranger tag definitions and tag-based policies."""

    def __init__(self) -> None:
        self.tags_created: int = 0
        self.policies_created: int = 0

    def _create_tag_definition(self, tag_def: dict[str, Any]) -> bool:
        """Create a tag definition in Ranger's tag store (idempotent).

        Args:
            tag_def: Tag definition dict with name, description, attributeDefs.

        Returns:
            True if created or already exists.
        """
        tag_name = tag_def["name"]
        try:
            # Check if tag already exists
            resp = requests.get(
                f"{RANGER_BASE_URL}/service/tags/tags",
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code == 200:
                existing_tags = resp.json()
                # Ranger returns tags as a dict keyed by ID or a list
                if isinstance(existing_tags, dict):
                    for tag_data in existing_tags.values():
                        if isinstance(tag_data, dict) and tag_data.get("name") == tag_name:
                            logger.info("Tag definition '%s' already exists", tag_name)
                            return True
                elif isinstance(existing_tags, list):
                    for tag_data in existing_tags:
                        if isinstance(tag_data, dict) and tag_data.get("name") == tag_name:
                            logger.info("Tag definition '%s' already exists", tag_name)
                            return True

            # Create tag definition
            payload = {
                "name": tag_name,
                "description": tag_def.get("description", ""),
                "attributeDefs": tag_def.get("attributeDefs", []),
            }
            resp = requests.post(
                f"{RANGER_BASE_URL}/service/tags/tags",
                json=payload,
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                logger.info("Created Ranger tag definition: %s", tag_name)
                self.tags_created += 1
                return True

            logger.warning(
                "Could not create tag definition '%s': %s %s",
                tag_name,
                resp.status_code,
                resp.text[:200],
            )
            return False

        except requests.RequestException as exc:
            logger.warning("Failed to create tag definition '%s': %s", tag_name, exc)
            return False

    def _create_tag_based_policy(self, policy: dict[str, Any]) -> bool:
        """Create a tag-based policy in Ranger (idempotent by name).

        Args:
            policy: Ranger policy dict with policyType and tag-based resources.

        Returns:
            True on success.
        """
        policy_name = policy.get("name", "<unnamed>")
        try:
            # Check if policy exists
            resp = requests.get(
                f"{RANGER_BASE_URL}/service/public/v2/api/policy",
                params={
                    "serviceName": policy.get("service", RANGER_SERVICE),
                    "policyName": policy_name,
                },
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code == 200 and resp.json():
                logger.info("Tag-based policy '%s' already exists", policy_name)
                return True

            # Create policy
            resp = requests.post(
                f"{RANGER_BASE_URL}/service/public/v2/api/policy",
                json=policy,
                auth=RANGER_AUTH,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                logger.info("Created tag-based policy: %s", policy_name)
                self.policies_created += 1
                return True
            if resp.status_code == 400 and "already exists" in resp.text:
                logger.info("Tag-based policy '%s' already exists", policy_name)
                return True

            logger.warning(
                "Could not create tag-based policy '%s': %s %s",
                policy_name,
                resp.status_code,
                resp.text[:200],
            )
            return False

        except requests.RequestException as exc:
            logger.warning("Failed to create tag-based policy '%s': %s", policy_name, exc)
            return False

    def setup_tags_and_policies(self) -> dict[str, int]:
        """Create all tag definitions and tag-based policies.

        Returns:
            Dict with tags_created and policies_created counts.
        """
        # Step 1: Create tag definitions
        logger.info("Creating Ranger tag definitions...")
        for tag_def in TAG_DEFINITIONS:
            self._create_tag_definition(tag_def)

        # Step 2: Create tag-based masking policy for PII
        pii_masking_policy: dict[str, Any] = {
            "policyType": 1,
            "service": RANGER_SERVICE,
            "name": "tag:pii_column_masking",
            "isEnabled": True,
            "resources": {
                "catalog": {"values": ["*"]},
                "schema": {"values": ["*"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "dataMaskPolicyItems": [
                {
                    "users": [],
                    "groups": ["data_analysts"],
                    "dataMaskInfo": {"dataMaskType": "MASK_HASH"},
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ],
            "policyLabels": [
                "source:ranger_tag_setup",
                "tag:pii",
                "classification_driven",
            ],
        }
        self._create_tag_based_policy(pii_masking_policy)

        # Step 3: Deny policy for sensitive data — deny external_users
        sensitive_deny_policy: dict[str, Any] = {
            "policyType": 0,
            "service": RANGER_SERVICE,
            "name": "tag:sensitive_deny_external",
            "isEnabled": True,
            "resources": {
                "catalog": {"values": ["*"]},
                "schema": {"values": ["*"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [],
            "denyPolicyItems": [
                {
                    "users": [],
                    "groups": ["external_users"],
                    "accesses": [
                        {"type": "select", "isAllowed": True},
                        {"type": "insert", "isAllowed": True},
                        {"type": "delete", "isAllowed": True},
                    ],
                }
            ],
            "policyLabels": [
                "source:ranger_tag_setup",
                "tag:sensitive",
                "classification_driven",
            ],
        }
        self._create_tag_based_policy(sensitive_deny_policy)

        # Step 4: Baseline deny for non-Immuta groups on Tier 2 datasets
        immuta_floor_policy: dict[str, Any] = {
            "policyType": 0,
            "service": RANGER_SERVICE,
            "name": "tag:immuta_fgac_ranger_floor",
            "isEnabled": True,
            "resources": {
                "catalog": {"values": ["*"]},
                "schema": {"values": ["*"]},
                "table": {"values": ["*"]},
                "column": {"values": ["*"]},
            },
            "policyItems": [],
            "denyPolicyItems": [
                {
                    "users": [],
                    "groups": ["non_immuta_users"],
                    "accesses": [{"type": "select", "isAllowed": True}],
                }
            ],
            "policyLabels": [
                "source:ranger_tag_setup",
                "tag:governance_tier_immuta_fgac",
                "classification_driven",
                "ranger_floor",
            ],
        }
        self._create_tag_based_policy(immuta_floor_policy)

        return {
            "tags_created": self.tags_created,
            "policies_created": self.policies_created,
        }
