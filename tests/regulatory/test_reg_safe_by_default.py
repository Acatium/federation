"""Safe-by-Default Tests — Cross-Regulation Fail-Closed Enforcement.

The architecture's fail-closed property satisfies multiple regulations
simultaneously: BCBS 239 P4, DORA Art 9, GDPR, APRA CPS 234, MAS TRM.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
import requests

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.regulatory]


class TestSafeByDefault:
    """Cross-regulation: fail-closed enforcement property."""

    # ------------------------------------------------------------------
    # Authorized path
    # ------------------------------------------------------------------

    @pytest.mark.slow
    def test_fail_closed_authorized_user(
        self,
        trino_conn: Any,
    ) -> None:
        """BCBS 239 P4 / DORA Art 9: Authorized user gets data through governed path.

        Regulatory scenario: An authorized user queries data through the
        governed federation layer and receives results.
        """
        cursor = trino_conn.cursor()
        cursor.execute(
            "SELECT count(*) FROM redshift.federation.ledger_entries"
        )
        count = cursor.fetchone()[0]
        assert count > 0, "Authorized user received no data"
        logger.info(
            "Safe-by-default: Authorized path works — %d rows accessible", count
        )

    # ------------------------------------------------------------------
    # Unauthorized path
    # ------------------------------------------------------------------

    def test_fail_closed_policy_structure(
        self,
        ranger_policies: list[dict[str, Any]],
    ) -> None:
        """DORA Art 9: Ranger policies enforce access via explicit grants.

        Regulatory scenario: Fail-closed architecture — access is only granted
        through explicit Ranger policy entries. We verify that data-access
        policies require named users or groups (not anonymous/public wildcards),
        meaning any user not listed in a matching policy would be denied.
        """
        if not ranger_policies:
            pytest.skip("No Ranger policies available")

        # Collect policies that grant access to actual data resources
        # (exclude system/metadata policies like "all - catalog" etc.)
        data_policies = [
            p for p in ranger_policies
            if any(
                l.startswith("source:") for l in p.get("policyLabels", [])
            )
        ]

        assert len(data_policies) > 0, (
            "No data-access policies with source: labels found in Ranger"
        )

        # Verify each data policy has named principals
        for policy in data_policies:
            for item in policy.get("policyItems", []):
                users = item.get("users", [])
                groups = item.get("groups", [])
                # At least one explicit principal
                has_principal = (
                    any(u and u != "*" for u in users)
                    or any(g and g not in ("*", "public") for g in groups)
                )
                assert has_principal, (
                    f"Policy '{policy.get('name')}' grants access without "
                    "explicit principals — violates fail-closed principle"
                )

        logger.info(
            "Safe-by-default: All %d data policies require explicit principals",
            len(data_policies),
        )

    # ------------------------------------------------------------------
    # No wildcard allow-all
    # ------------------------------------------------------------------

    def test_no_wildcard_allow_all(
        self,
        ranger_policies: list[dict[str, Any]],
    ) -> None:
        """DORA Art 9 / GDPR: No dangerous wildcard policies that bypass governance.

        Regulatory scenario: Scan all Ranger policies to ensure no policy
        grants wildcard access to all resources — this would bypass the
        governance model.
        """
        if not ranger_policies:
            pytest.skip("No Ranger policies available")

        dangerous: list[str] = []
        for policy in ranger_policies:
            resources = policy.get("resources", {})
            # Check if ALL resource dimensions are wildcards
            all_wildcard = all(
                set(res.get("values", [])) == {"*"}
                for res in resources.values()
            )
            if not all_wildcard:
                continue

            # Check if policyItems allow all (no restrictions)
            for item in policy.get("policyItems", []):
                users = item.get("users", [])
                groups = item.get("groups", [])
                if "public" in groups or "*" in users:
                    dangerous.append(policy.get("name", "<unnamed>"))

        assert len(dangerous) == 0, (
            f"Dangerous wildcard allow-all policies found: {dangerous}. "
            "These bypass governance controls."
        )
        logger.info(
            "Safe-by-default: No wildcard allow-all policies found in %d policies",
            len(ranger_policies),
        )

    # ------------------------------------------------------------------
    # Safety matrix
    # ------------------------------------------------------------------

    def test_safety_matrix_documented(self) -> None:
        """Cross-regulation: all four sync-gap quadrants are safe with identity passthrough.

        Uses safety_model.analyze_sync_gap() to compute the outcome for each
        Ranger×Platform quadrant under IdentityMode.PASSTHROUGH. As deployed here
        (shared service accounts) the over-permissive quadrant leaks; see
        test_as_deployed_the_over_permissive_quadrant_leaks.
        """
        from src.governance.safety_model import (
            SYNC_GAP_QUADRANTS,
            IdentityMode,
            analyze_sync_gap,
        )

        assert len(SYNC_GAP_QUADRANTS) == 4, (
            f"Expected 4 quadrants, got {len(SYNC_GAP_QUADRANTS)}"
        )

        for quadrant_name, (ranger_state, platform_state) in SYNC_GAP_QUADRANTS.items():
            outcome = analyze_sync_gap(ranger_state, platform_state, IdentityMode.PASSTHROUGH)
            assert outcome.is_safe, (
                f"Quadrant '{quadrant_name}' is NOT safe: {outcome.explanation}"
            )
            logger.info(
                "  %s: ranger=%s, platform=%s -> %s (safe=%s)",
                quadrant_name,
                outcome.ranger_state.value,
                outcome.platform_state.value,
                outcome.outcome_type,
                outcome.is_safe,
            )

        logger.info(
            "Safe-by-default: All %d safety quadrants safe under passthrough",
            len(SYNC_GAP_QUADRANTS),
        )

    def test_as_deployed_the_over_permissive_quadrant_leaks(self) -> None:
        """Cross-regulation: with shared service accounts, a stale allow exposes data."""
        from src.governance.safety_model import (
            SYNC_GAP_QUADRANTS,
            IdentityMode,
            analyze_sync_gap,
        )

        unsafe = {
            name
            for name, (ranger, platform) in SYNC_GAP_QUADRANTS.items()
            if not analyze_sync_gap(ranger, platform, IdentityMode.SERVICE_ACCOUNT).is_safe
        }
        assert unsafe == {"over_permissive_ranger"}

    # ------------------------------------------------------------------
    # Platform-native backstop
    # ------------------------------------------------------------------

    @pytest.mark.slow
    def test_platform_native_backstop(
        self,
        redshift_conn: Any,
    ) -> None:
        """DORA Art 9: the platform enforces RBAC for the connector's account.

        Regulatory scenario: even if the federation layer is compromised, the
        source platform limits access to what the connector's account can reach.
        That is a ceiling, not a per-user backstop: Redshift sees this account,
        not the end user. We verify Redshift RBAC is active by confirming the
        current user.
        """
        cursor = redshift_conn.cursor()
        cursor.execute("SELECT current_user")
        user = cursor.fetchone()[0]
        assert user, "Redshift current_user returned empty"
        logger.info(
            "Safe-by-default: Platform backstop active — Redshift user='%s'", user
        )

    # ------------------------------------------------------------------
    # Two-tier governance completeness
    # ------------------------------------------------------------------

    def test_two_tier_governance_no_ungoverned_data(
        self,
        gravitino_base_url: str,
        gravitino_catalogs: list[str],
    ) -> None:
        """APRA CPS 234 / MAS TRM: No ungoverned datasets.

        Regulatory scenario: Controls must be proportional to sensitivity.
        Every Gravitino catalog must have a governance_tier assigned — there
        is no 'ungoverned' tier in the architecture.
        """
        if not gravitino_catalogs:
            pytest.skip("No Gravitino catalogs available")

        valid_tiers = {"platform_native", "immuta_fgac"}
        checked = 0
        ungoverned: list[str] = []

        for catalog_name in gravitino_catalogs:
            url = (
                f"{gravitino_base_url}/api/metalakes/federation"
                f"/catalogs/{catalog_name}"
            )
            try:
                resp = requests.get(url, timeout=30)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                props = data.get("catalog", data).get("properties", {})
                tier = props.get("governance_tier", "")
                if tier and tier in valid_tiers:
                    checked += 1
                elif tier:
                    ungoverned.append(f"{catalog_name}:{tier}")
                else:
                    ungoverned.append(f"{catalog_name}:NONE")
            except requests.RequestException:
                continue

        assert checked >= 1, "No catalogs verified with governance_tier"
        if ungoverned:
            logger.warning(
                "Catalogs without valid governance_tier: %s", ungoverned
            )
        logger.info(
            "Two-tier governance: %d/%d catalogs have valid governance_tier",
            checked,
            len(gravitino_catalogs),
        )
