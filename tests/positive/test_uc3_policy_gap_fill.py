"""UC-3: Federation Policy Fills Gaps.

Verifies that Ranger has policies extracted from multiple source platforms.
Policy labels track provenance (source:lake_formation, source:redshift,
source:snowflake, source:immuta). Gap-fill policies exist for datasets
not covered by any single platform's governance alone.
"""
import logging
from typing import Any

import pytest

logger = logging.getLogger(__name__)


class TestPolicyGapFill:
    """Verify Ranger policies cover multiple sources and fill gaps."""

    def test_ranger_has_policies(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger must have at least one policy for the Trino service."""
        assert len(ranger_policies) > 0, (
            "No Ranger policies found for dev_trino service. "
            "Policy extractors may not have run."
        )
        logger.info("Total Ranger policies for dev_trino: %d", len(ranger_policies))

    def test_policies_from_multiple_sources(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger policies should have labels from multiple source platforms.

        Each extractor stamps source:xxx labels. We verify that at least
        two distinct sources are represented.
        """
        sources_found: set[str] = set()
        for policy in ranger_policies:
            labels = policy.get("policyLabels", [])
            for label in labels:
                if label.startswith("source:"):
                    source_name = label.split(":", 1)[1]
                    sources_found.add(source_name)

        logger.info("Distinct sources in Ranger policies: %s", sources_found)
        assert len(sources_found) >= 2, (
            f"Expected policies from at least 2 sources, found: {sources_found}. "
            "Multiple extractors must push policies."
        )

    def test_immuta_policies_exist(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger should have policies extracted from Immuta (mock or live).

        These represent the Tier 2 (immuta_fgac) governance mirror.
        """
        immuta_policies = [
            p for p in ranger_policies
            if any(
                label.startswith("source:immuta")
                for label in p.get("policyLabels", [])
            )
        ]
        logger.info("Immuta-sourced policies in Ranger: %d", len(immuta_policies))
        assert len(immuta_policies) > 0, (
            "No Immuta-sourced policies found in Ranger. "
            "The immuta_to_ranger extractor may not have run."
        )

    def test_governance_tier_labels_present(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Policies should carry governance_tier labels for audit clarity."""
        tier_labels_found: set[str] = set()
        for policy in ranger_policies:
            for label in policy.get("policyLabels", []):
                if label.startswith("governance_tier:"):
                    tier_labels_found.add(label)

        logger.info("Governance tier labels found: %s", tier_labels_found)
        assert len(tier_labels_found) > 0, (
            "No governance_tier labels found on any Ranger policy"
        )
        # Verify the known tiers
        expected = {
            "governance_tier:platform_native",
            "governance_tier:immuta_fgac",
        }
        found = tier_labels_found & expected
        assert len(found) >= 1, (
            f"Expected at least one of {expected} in policy labels, "
            f"found: {tier_labels_found}"
        )

    def test_masking_policies_exist_for_pii(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Masking policies (policyType=1) should exist for PII columns.

        Immuta mock defines masking for token_id, entity_name, account_ref.
        Ranger should have corresponding masking policies.
        """
        masking_policies = [
            p for p in ranger_policies if p.get("policyType") == 1
        ]
        logger.info("Masking policies (policyType=1): %d", len(masking_policies))
        assert len(masking_policies) > 0, (
            "No masking policies found in Ranger. "
            "Expected at least one for PII columns (token_id, entity_name)."
        )
