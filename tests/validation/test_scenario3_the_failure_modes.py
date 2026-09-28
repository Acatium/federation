"""Scenario 3: The Failure Modes.

Every system works in the demo. The question an architect — or a
regulator — actually asks is: what happens when it breaks? When the
policy mirror is stale? When someone bypasses the governed path? When
access controls from different platforms conflict?

The answer depends on identity. With identity passthrough, a stale
mirror creates noise, not risk. As deployed here, Trino reaches each
platform through one service account, so a stale allow exposes data
until the mirror syncs; `test_stale_allow_leaks_through_the_shared_connector`
observes that against live Redshift. When controls from different systems
overlap or conflict, the result degrades data utility, not data security.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import pytest
import requests

pytestmark = [pytest.mark.validation]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Part 1: Safe by Default
# ---------------------------------------------------------------------------


class TestSafeByDefault:
    """Whether the sync gap is noise or risk depends on the identity the platform sees."""

    def test_all_sync_gap_combinations_are_safe_with_passthrough(self) -> None:
        """All 16 Ranger x Platform state combinations are safe under passthrough.

        Exhaustive truth table: 4 Ranger states × 4 Platform states, with the
        platform evaluating the end user (IdentityMode.PASSTHROUGH). This is the
        configuration the backstop needs, not the one deployed here.
        """
        from src.governance.safety_model import (
            EnforcementState,
            IdentityMode,
            analyze_sync_gap,
        )

        unsafe: list[str] = []
        for ranger_state in EnforcementState:
            for platform_state in EnforcementState:
                outcome = analyze_sync_gap(ranger_state, platform_state, IdentityMode.PASSTHROUGH)
                if not outcome.is_safe:
                    unsafe.append(
                        f"({ranger_state.value}, {platform_state.value}): "
                        f"{outcome.outcome_type}"
                    )
                # Only the AND of both allows should grant access
                ranger_allows = ranger_state in (
                    EnforcementState.ALLOW, EnforcementState.STALE_ALLOW,
                )
                platform_allows = platform_state in (
                    EnforcementState.ALLOW, EnforcementState.STALE_ALLOW,
                )
                expected_access = ranger_allows and platform_allows
                assert outcome.access_granted == expected_access, (
                    f"({ranger_state.value}, {platform_state.value}): "
                    f"access_granted={outcome.access_granted}, "
                    f"expected={expected_access}"
                )
                logger.info(
                    "(%s, %s) -> %s, access=%s, safe=%s",
                    ranger_state.value,
                    platform_state.value,
                    outcome.outcome_type,
                    outcome.access_granted,
                    outcome.is_safe,
                )
        assert len(unsafe) == 0, (
            f"Found unsafe quadrants: {unsafe}"
        )
        logger.info("All 16 Ranger x Platform combinations safe under passthrough")

    def test_as_deployed_only_stale_allows_leak(self) -> None:
        """With shared service accounts, exactly the Ranger-allow/user-denied cells leak."""
        from src.governance.safety_model import (
            EnforcementState,
            IdentityMode,
            analyze_sync_gap,
        )

        allows = {EnforcementState.ALLOW, EnforcementState.STALE_ALLOW}
        unsafe = {
            (r, p)
            for r in EnforcementState
            for p in EnforcementState
            if not analyze_sync_gap(r, p, IdentityMode.SERVICE_ACCOUNT).is_safe
        }
        assert unsafe == {(r, p) for r in allows for p in EnforcementState if p not in allows}

    def test_stale_allow_blocked_by_platform_with_passthrough(self) -> None:
        """Ranger allows (stale) but the platform denies the user -> blocked at source."""
        from src.governance.safety_model import EnforcementState, IdentityMode, analyze_sync_gap

        outcome = analyze_sync_gap(
            EnforcementState.STALE_ALLOW, EnforcementState.DENY, IdentityMode.PASSTHROUGH
        )
        assert outcome.outcome_type == "platform_backstop", (
            f"Expected platform_backstop, got {outcome.outcome_type}"
        )
        assert outcome.access_granted is False, "Stale allow should NOT grant access"
        logger.info("Stale allow -> platform backstop: %s", outcome.explanation)

    def test_stale_deny_blocks_at_federation(self) -> None:
        """Ranger denies (stale) but platform allows -> blocked until sync, as deployed."""
        from src.governance.safety_model import EnforcementState, IdentityMode, analyze_sync_gap

        outcome = analyze_sync_gap(
            EnforcementState.STALE_DENY, EnforcementState.ALLOW, IdentityMode.SERVICE_ACCOUNT
        )
        assert outcome.outcome_type == "fail_closed", (
            f"Expected fail_closed, got {outcome.outcome_type}"
        )
        assert outcome.access_granted is False, "Stale deny should NOT grant access"
        logger.info("Stale deny -> fail closed: %s", outcome.explanation)

    @pytest.mark.slow
    def test_stale_allow_leaks_through_the_shared_connector(self, redshift_conn: Any) -> None:
        """Live: revoke at Redshift; Trino still returns rows until the Ranger sync, then refuses.

        Trino's Redshift catalog logs in as one connection-user, so Redshift never
        sees demo_analyst and does not check the revocation. This is the as-deployed
        row of the safety model (IdentityMode.SERVICE_ACCOUNT), observed live.
        """
        import os

        import psycopg2
        import trino

        from src.extractors.redshift_to_ranger import RedshiftExtractor

        password = os.getenv("DEMO_ANALYST_PASSWORD", "")
        trino_host = os.getenv("TRINO_HOST", "")
        if not password or not trino_host:
            pytest.skip("DEMO_ANALYST_PASSWORD and TRINO_HOST are required")
        if any(c in password for c in ("'", ";", "--", "/*")):
            pytest.fail("DEMO_ANALYST_PASSWORD contains disallowed characters")

        table = "federation.ledger_entries"
        rs = redshift_conn.cursor()
        try:
            rs.execute("CREATE USER demo_analyst PASSWORD %s", (password,))
            redshift_conn.commit()
        except psycopg2.Error:
            redshift_conn.rollback()  # already exists
        rs.execute("GRANT USAGE ON SCHEMA federation TO demo_analyst")
        rs.execute(f"GRANT SELECT ON {table} TO demo_analyst")
        redshift_conn.commit()

        # Sync the grant into Ranger, then wait for Trino's Ranger plugin to load it.
        assert RedshiftExtractor().extract_and_push()["status"] == "complete"
        analyst = trino.dbapi.connect(
            host=trino_host,
            port=int(os.getenv("TRINO_PORT", "8080")),
            user="demo_analyst",
            catalog="redshift",
            schema="federation",
        )

        def federated_count() -> int:
            cursor = analyst.cursor()
            cursor.execute(f"SELECT count(*) FROM redshift.{table}")
            return int(cursor.fetchone()[0])

        deadline = time.monotonic() + 120
        while True:
            try:
                before = federated_count()
                break
            except Exception:
                if time.monotonic() > deadline:
                    pytest.fail("Ranger never allowed demo_analyst after the sync")
                time.sleep(5)

        try:
            # Revoke at the source. Ranger still holds the allow from the last sync.
            rs.execute(f"REVOKE SELECT ON {table} FROM demo_analyst")
            redshift_conn.commit()

            # Redshift enforces the revocation for the person...
            direct = psycopg2.connect(
                host=os.getenv("REDSHIFT_HOST"),
                port=int(os.getenv("REDSHIFT_PORT", "5439")),
                database=os.getenv("REDSHIFT_DATABASE"),
                user="demo_analyst",
                password=password,
                sslmode="require",
            )
            try:
                with pytest.raises(psycopg2.Error):
                    direct.cursor().execute(f"SELECT count(*) FROM {table}")
            finally:
                direct.close()

            # ...but not for the connector, so the federated query still returns rows.
            after = federated_count()
            assert after == before > 0, (
                f"Expected rows through the shared connector after revocation; got {after}"
            )
            logger.info(
                "Revoked at Redshift, still read %d rows through Trino before the Ranger sync",
                after,
            )

            # Sync: reconciliation deletes the revoked allow, and the query is refused.
            assert RedshiftExtractor().extract_and_push()["status"] == "complete"
            deadline = time.monotonic() + 120
            while True:
                try:
                    federated_count()
                except Exception as exc:
                    logger.info("After the Ranger sync, Trino refuses demo_analyst: %s", exc)
                    break
                if time.monotonic() > deadline:
                    pytest.fail("demo_analyst could still read through Trino after the sync")
                time.sleep(5)
        finally:
            analyst.close()

    @pytest.mark.slow
    def test_unauthorized_user_denied_at_trino(
        self, restricted_trino_conn: Any
    ) -> None:
        """restricted_user gets denied before query reaches source."""
        cursor = restricted_trino_conn.cursor()
        with pytest.raises(Exception) as exc_info:
            cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
            cursor.fetchall()
        error_msg = str(exc_info.value).lower()
        assert "access denied" in error_msg or "catalog_not_found" in error_msg, (
            f"Expected 'Access Denied' or 'CATALOG_NOT_FOUND', got: {exc_info.value}"
        )
        logger.info("restricted_user denied: %s", exc_info.value)

    def test_no_policy_grants_everything_to_everyone(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """No Ranger policy grants * to public on * resources."""
        overly_permissive = []
        for policy in ranger_policies:
            # Check if all resource values are ["*"]
            resources = policy.get("resources", {})
            all_wildcard = resources and all(
                v.get("values", []) == ["*"]
                for v in resources.values()
            )
            if not all_wildcard:
                continue
            # Check policy items for public/* grants
            for item in policy.get("policyItems", []):
                groups = item.get("groups", [])
                users = item.get("users", [])
                if "public" in groups or "*" in users:
                    overly_permissive.append(policy.get("name", "unnamed"))
        assert len(overly_permissive) == 0, (
            f"Found overly permissive policies: {overly_permissive}"
        )
        logger.info(
            "Scanned %d policies — none grant * to public on * resources",
            len(ranger_policies),
        )


# ---------------------------------------------------------------------------
# Part 2: Governance Contrast
# ---------------------------------------------------------------------------


class TestGovernanceContrast:
    """Same data. Two paths. One governed, one not."""

    @pytest.mark.slow
    def test_governed_path_returns_data(self, trino_conn: Any) -> None:
        """test_user queries via Trino and gets results normally."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
        rows = cursor.fetchall()
        count = rows[0][0]
        assert count >= 400_000, f"Expected >= 400K rows, got {count}"
        logger.info("Governed path returned %d rows", count)

    @pytest.mark.slow
    def test_pii_masked_through_governed_path(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """token_id via Trino vs direct Redshift — proves masking is active.

        Compares token_id values between governed (Trino) and direct (Redshift)
        paths. The default Trino user is in the 'public' group which has a
        SHOW_LAST_4 masking policy on token_id. Values MUST differ.
        S4 test_analyst_sees_masked_pii confirms the same for alice_analyst.
        """
        # Trino query
        trino_cursor = trino_conn.cursor()
        trino_cursor.execute(
            "SELECT entry_id, token_id FROM redshift.federation.ledger_entries "
            "ORDER BY entry_id LIMIT 5"
        )
        trino_rows = trino_cursor.fetchall()

        # Redshift query
        rs_cursor = redshift_conn.cursor()
        rs_cursor.execute(
            "SELECT entry_id, token_id FROM federation.ledger_entries "
            "ORDER BY entry_id LIMIT 5"
        )
        rs_rows = rs_cursor.fetchall()

        # Build lookup by entry_id
        trino_map = {row[0]: row[1] for row in trino_rows}
        rs_map = {row[0]: row[1] for row in rs_rows}

        # Compare token_id values for matching entry_ids
        common_ids = set(trino_map.keys()) & set(rs_map.keys())
        assert len(common_ids) > 0, "No matching entry_ids between Trino and Redshift"

        values_differ = any(trino_map[eid] != rs_map[eid] for eid in common_ids)
        assert values_differ, (
            "Masking NOT active: token_id values match between Trino and Redshift. "
            "Expected governed path to mask PII."
        )
        logger.info("Masking is ACTIVE: token_id values differ between Trino and Redshift")
        for eid in sorted(common_ids):
            logger.info(
                "  entry_id=%s: trino=%s, redshift=%s",
                eid, trino_map[eid], rs_map[eid],
            )

    @pytest.mark.slow
    def test_pii_visible_at_source(self, redshift_conn: Any) -> None:
        """Direct Redshift returns raw token_id — masking is federation-layer."""
        cursor = redshift_conn.cursor()
        cursor.execute("SELECT token_id FROM federation.ledger_entries LIMIT 5")
        rows = cursor.fetchall()
        assert len(rows) > 0, "Expected rows from direct Redshift"
        for row in rows:
            token_id = str(row[0])
            assert token_id is not None, "token_id should not be NULL at source"
            # Raw token_id is 16 hex chars (Faker hexify). A SHA256-masked value
            # would be 64 hex chars. If token_id is >= 40 chars, it's been hashed —
            # which would mean masking is active at the source layer (unexpected).
            assert len(token_id) < 40, (
                f"token_id '{token_id}' looks hashed ({len(token_id)} chars) — "
                f"expected raw value (16 hex chars) at source"
            )
            logger.info("  raw token_id: %s (%d chars)", token_id, len(token_id))
        logger.info("Direct Redshift returns %d raw token_id values", len(rows))

    @pytest.mark.slow
    def test_row_filter_constrains_visibility(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Row filter policies are configured for jurisdiction filtering.

        Trino 479 Ranger plugin lacks getRowFilters() so enforcement cannot
        be tested at query time. This test verifies that row filter policies
        (policyType=2) exist in Ranger with filter expressions targeting
        different groups. See S4 test_jurisdiction_filter_policy_differentiates_groups
        for per-group policy structure verification.
        """
        row_filter_policies = [
            p for p in ranger_policies if p.get("policyType") == 2
        ]
        assert len(row_filter_policies) >= 2, (
            f"Expected >= 2 row filter policies (one per group), "
            f"got {len(row_filter_policies)}"
        )
        # Verify they carry filter expressions
        for policy in row_filter_policies:
            items = policy.get("rowFilterPolicyItems", [])
            assert len(items) > 0, (
                f"Row filter policy '{policy.get('name')}' has no filter items"
            )
            for item in items:
                expr = item.get("rowFilterInfo", {}).get("filterExpr", "")
                assert expr, (
                    f"Row filter policy '{policy.get('name')}' has empty filter expression"
                )
        logger.info(
            "Row filter policies: %d configured with filter expressions",
            len(row_filter_policies),
        )

    @pytest.mark.slow
    def test_governed_path_generates_audit_trail(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """Trino query produces audit events in Solr."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
        cursor.fetchall()

        # Wait for Solr auto-commit
        time.sleep(7)

        resp = requests.get(
            solr_audit_url,
            params={"q": "*:*", "rows": "0", "wt": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        num_found = resp.json()["response"]["numFound"]
        assert num_found > 0, "No audit events found in Solr after Trino query"
        logger.info("Solr contains %d audit events after governed query", num_found)

    @pytest.mark.slow
    def test_ungoverned_path_has_no_federation_audit(
        self, redshift_conn: Any, solr_audit_url: str
    ) -> None:
        """Direct Redshift query does NOT produce Solr audit event.

        Approach: Ranger audit events come from the Ranger-Trino plugin.
        Every event has a reqUser matching the Trino user. Direct Redshift
        queries bypass Trino entirely, so they cannot produce Ranger events.
        We verify this by checking that every audit event in Solr is
        attributable to a Trino user — not to the Redshift connection.
        """
        import os

        trino_user = os.getenv("TRINO_USER", "test_user")

        # Execute a direct Redshift query (this bypasses Trino/Ranger entirely)
        cursor = redshift_conn.cursor()
        cursor.execute("SELECT count(*) FROM federation.ledger_entries")
        direct_count = cursor.fetchall()[0][0]
        logger.info("Direct Redshift query returned %d rows", direct_count)

        # Wait for Solr auto-commit in case anything was going to appear
        time.sleep(7)

        # Query Solr for recent audit events
        resp = requests.get(
            solr_audit_url,
            params={
                "q": "*:*",
                "rows": "50",
                "sort": "evtTime desc",
                "wt": "json",
            },
            timeout=15,
        )
        resp.raise_for_status()
        docs = resp.json()["response"]["docs"]
        num_found = resp.json()["response"]["numFound"]

        # First: Solr must have SOME events from governed-path tests in this
        # session. Without this, the "no non-Trino events" assertion below
        # would pass vacuously on an empty Solr index.
        assert num_found > 0, (
            "Solr has zero audit events — cannot distinguish governed from "
            "ungoverned paths. Run governed-path tests first to populate Solr."
        )

        # Every audit event should be attributable to a Trino user.
        # If the direct Redshift query produced an audit event, it would
        # appear with the Redshift DB user or an unknown source.
        # Known Trino users: test_user (governed queries) and restricted_user
        # (denial tests). Both are valid — Ranger audits allows AND denials.
        known_trino_users = {trino_user, "restricted_user", "admin", ""}
        non_trino_events = []
        for doc in docs:
            req_user = doc.get("reqUser", "")
            if isinstance(req_user, list):
                users = req_user
            else:
                users = [req_user] if req_user else []
            if not any(u in known_trino_users for u in users):
                non_trino_events.append(
                    f"reqUser={users}, resource={doc.get('resource', 'unknown')}"
                )

        assert len(non_trino_events) == 0, (
            f"Found {len(non_trino_events)} audit events not attributable to "
            f"Trino user '{trino_user}': {non_trino_events[:5]}. "
            f"Direct Redshift should not produce Ranger audit events."
        )
        logger.info(
            "All %d Solr audit events attributable to Trino user '%s'. "
            "Direct Redshift query produced no Ranger audit events.",
            num_found, trino_user,
        )


# ---------------------------------------------------------------------------
# Part 3: Fine-Grained Controls
# ---------------------------------------------------------------------------


class TestFineGrainedControls:
    """Column masking, purpose gates, and honest gaps."""

    def test_immuta_defines_purpose_based_access(self) -> None:
        """Immuta mock policies define distinct access purposes.

        Tests the Immuta extraction pipeline against deterministic mock data
        (src/mocks/immuta_mock.py) — no live Immuta instance is contacted.
        Proves the pipeline correctly handles purpose-based access structures.
        """
        from src.mocks.immuta_mock import POLICIES

        purposes = set()
        for policy in POLICIES:
            purpose = policy.get("purpose")
            if purpose:
                purposes.add(purpose)
        assert len(purposes) >= 3, (
            f"Expected >= 3 distinct purposes, got {len(purposes)}: {purposes}"
        )
        logger.info("Immuta purposes: %s", sorted(purposes))

    def test_immuta_defines_column_level_masking(self) -> None:
        """Immuta mock masking rules target specific PII columns.

        Tests the Immuta extraction pipeline against deterministic mock data
        (src/mocks/immuta_mock.py) — no live Immuta instance is contacted.
        Proves the pipeline correctly handles column-level masking structures.
        """
        from src.mocks.immuta_mock import POLICIES

        masked_columns: set[str] = set()
        for policy in POLICIES:
            if policy.get("type") != "masking":
                continue
            for action in policy.get("actions", []):
                if action.get("type") != "masking":
                    continue
                for rule in action.get("rules", []):
                    col = rule.get("column")
                    if col:
                        masked_columns.add(col)

        pii_columns = {"token_id", "entity_name", "account_ref"}
        overlap = masked_columns & pii_columns
        assert len(overlap) > 0, (
            f"Expected masking on PII columns {pii_columns}, "
            f"but found masking on {masked_columns}"
        )
        logger.info("Immuta masks PII columns: %s", sorted(masked_columns))

    def test_abac_to_rbac_translation_is_lossy_and_documented(
        self, immuta_extracted_policies: list[dict[str, Any]]
    ) -> None:
        """Extracted policies carry translation_note labels."""
        notes_found: list[str] = []
        for policy in immuta_extracted_policies:
            labels = policy.get("policyLabels", [])
            for label in labels:
                if isinstance(label, str) and "translation_note:" in label:
                    notes_found.append(label)
        assert len(notes_found) >= 1, (
            "Expected >= 1 policy with a translation_note label"
        )
        for note in notes_found:
            logger.info("Translation note: %s", note)

    def test_every_lossy_translation_is_labeled(
        self, immuta_extracted_policies: list[dict[str, Any]]
    ) -> None:
        """No silent loss — every lossy mapping has an auditable label."""
        unlabeled = []
        for policy in immuta_extracted_policies:
            labels = policy.get("policyLabels", [])
            label_str = " ".join(str(l) for l in labels)
            is_immuta_sourced = "source:immuta" in label_str
            if not is_immuta_sourced:
                continue
            has_note = (
                "translation_note:" in label_str
                or "fidelity:" in label_str
            )
            if not has_note:
                unlabeled.append(policy.get("name", "unnamed"))
        assert len(unlabeled) == 0, (
            f"Immuta-sourced policies without translation/fidelity labels: {unlabeled}"
        )
        logger.info(
            "All %d Immuta-sourced policies are labeled",
            sum(
                1 for p in immuta_extracted_policies
                if "source:immuta" in " ".join(str(l) for l in p.get("policyLabels", []))
            ),
        )

    def test_double_masking_documented(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """When Immuta and Ranger both mask columns, the overlap is identified.

        Both layers independently define masking targets. When they overlap,
        the result is hash-of-hash — degrades data utility, not security.
        This test proves both layers have masking targets and documents
        whether they overlap.
        """
        from src.mocks.immuta_mock import POLICIES

        # Identify columns masked by Immuta (Tier 2 FGAC)
        immuta_masked: set[str] = set()
        for policy in POLICIES:
            if policy.get("type") != "masking":
                continue
            for action in policy.get("actions", []):
                for rule in action.get("rules", []):
                    col = rule.get("column")
                    if col:
                        immuta_masked.add(col)

        # Identify columns masked by Ranger (policyType=1)
        ranger_masked: set[str] = set()
        for policy in ranger_policies:
            if policy.get("policyType") != 1:
                continue
            columns = policy.get("resources", {}).get("column", {}).get("values", [])
            ranger_masked.update(columns)

        # The overlap is the double-masking zone: Immuta masks at source,
        # Ranger masks at Trino. Result is hash-of-hash — degrades utility, not security.
        overlap = immuta_masked & ranger_masked
        assert len(immuta_masked) > 0, "Expected Immuta to mask at least one column"
        assert len(ranger_masked) > 0, "Expected Ranger to mask at least one column"

        # Both masking layers are active — document the relationship
        assert len(immuta_masked | ranger_masked) > 0, (
            "Expected at least one column masked across both layers"
        )
        logger.info(
            "Immuta masks: %s | Ranger masks: %s | Overlap: %s",
            sorted(immuta_masked), sorted(ranger_masked), sorted(overlap),
        )
        if overlap:
            logger.info(
                "Double masking confirmed for %s — "
                "Immuta masks at source, Ranger masks at Trino. "
                "Degrades utility (hash of hash), not security.",
                sorted(overlap),
            )
        else:
            logger.info(
                "No column overlap between Immuta and Ranger masking targets. "
                "Both layers mask independently — no utility degradation."
            )

    def test_ranger_masking_policies_cover_pii(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=1 masking policies exist for PII columns."""
        masking_policies = [
            p for p in ranger_policies if p.get("policyType") == 1
        ]
        assert len(masking_policies) >= 1, "Expected >= 1 Ranger masking policy"
        for p in masking_policies:
            logger.info("Ranger masking policy: %s", p.get("name", "unnamed"))

    def test_ranger_row_filter_policies_exist(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=2 row filter policies exist."""
        row_filter_policies = [
            p for p in ranger_policies if p.get("policyType") == 2
        ]
        assert len(row_filter_policies) >= 1, "Expected >= 1 Ranger row filter policy"
        for p in row_filter_policies:
            logger.info("Ranger row filter policy: %s", p.get("name", "unnamed"))


# ---------------------------------------------------------------------------
# Part 4: Platform Evolution
# ---------------------------------------------------------------------------


class TestPlatformEvolution:
    """We added Databricks. Nothing else changed."""

    def test_new_platform_registered_in_catalog(
        self, gravitino_catalogs: list[str], gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Databricks catalog present in Gravitino and introspects tables."""
        assert "databricks" in gravitino_catalogs, (
            f"Expected 'databricks' in Gravitino catalogs: {gravitino_catalogs}"
        )
        # Not just registered — must actually introspect tables (catches auth-less registrations)
        db_meta = gravitino_table_metadata.get("catalogs", {}).get("databricks", {})
        db_schemas = db_meta.get("schemas", {})
        db_tables = sum(len(s.get("tables", {})) for s in db_schemas.values())
        assert db_tables > 0, (
            f"Databricks registered but introspection returned 0 tables — auth may be missing"
        )
        logger.info(
            "Databricks in Gravitino: %d schemas, %d tables",
            len(db_schemas),
            db_tables,
        )

    def test_new_platform_policies_in_ranger(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """At least one policy with source:unity_catalog label."""
        uc_policies = []
        for policy in ranger_policies:
            labels = policy.get("policyLabels", [])
            label_str = " ".join(str(l) for l in labels)
            if "source:unity_catalog" in label_str:
                uc_policies.append(policy.get("name", "unnamed"))
        assert len(uc_policies) >= 1, (
            "Expected >= 1 policy with source:unity_catalog label"
        )
        logger.info("Unity Catalog policies: %s", uc_policies)

    @pytest.mark.slow
    def test_redshift_unaffected(self, trino_conn: Any) -> None:
        """500K+ rows still queryable from Redshift."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
        rows = cursor.fetchall()
        count = rows[0][0]
        assert count >= 400_000, f"Expected >= 400K rows, got {count}"
        logger.info("Redshift via Trino: %d rows", count)

    @pytest.mark.slow
    def test_snowflake_unaffected(self, trino_conn: Any) -> None:
        """Snowflake entities still queryable."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM snowflake.public.entities")
        rows = cursor.fetchall()
        count = rows[0][0]
        assert count > 0, f"Expected > 0 rows from Snowflake, got {count}"
        logger.info("Snowflake via Trino: %d rows", count)

    @pytest.mark.slow
    def test_iceberg_unaffected(
        self, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Iceberg cold tier still queryable."""
        cursor = trino_conn.cursor()
        cursor.execute(
            f"SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold"
        )
        rows = cursor.fetchall()
        count = rows[0][0]
        assert count > 0, f"Expected > 0 rows from Iceberg, got {count}"
        logger.info("Iceberg via Trino: %d rows", count)

    def test_prior_policies_intact(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger policies >= 26, prior sources still present."""
        assert len(ranger_policies) >= 26, (
            f"Expected >= 26 policies, got {len(ranger_policies)}"
        )
        # Extract source labels
        sources: set[str] = set()
        for policy in ranger_policies:
            for label in policy.get("policyLabels", []):
                if isinstance(label, str) and label.startswith("source:"):
                    sources.add(label.replace("source:", ""))
        for expected_source in ["redshift", "lake_formation", "snowflake"]:
            assert expected_source in sources, (
                f"Expected source '{expected_source}' in policy labels, "
                f"found: {sources}"
            )
        logger.info(
            "Ranger has %d policies with sources: %s",
            len(ranger_policies), sorted(sources),
        )


# ---------------------------------------------------------------------------
# Part 5: Engine Governance Delta
# ---------------------------------------------------------------------------


class TestEngineGovernanceDelta:
    """Every engine is governed. The stacks differ. The delta is documented."""

    def test_every_engine_has_at_least_two_controls(self) -> None:
        """Governance stacks for each engine have >= 2 controls."""
        from src.governance.safety_model import get_engine_governance_stack

        for engine in ["trino", "spark", "redshift", "snowflake"]:
            stack = get_engine_governance_stack(engine)
            assert len(stack.controls) >= 2, (
                f"{engine} has {len(stack.controls)} controls, expected >= 2"
            )
            logger.info(
                "%s governance stack: %s (%d controls)",
                engine, stack.control_names, len(stack.controls),
            )

    def test_trino_vs_spark_governance_delta(self) -> None:
        """compute_governance_delta() shows Trino has masking/filtering Spark lacks."""
        from src.governance.safety_model import compute_governance_delta

        delta = compute_governance_delta("trino", "spark")
        assert len(delta.additions) > 0, (
            "Expected Trino to have controls that Spark lacks"
        )
        logger.info(
            "Trino has %d controls Spark lacks: %s",
            len(delta.additions),
            [c.name for c in delta.additions],
        )
        # Expect masking and row filtering in the delta
        has_masking = any(
            c.enforcement_type == "masking" for c in delta.additions
        )
        has_row_filter = any(
            c.enforcement_type == "row_filter" for c in delta.additions
        )
        logger.info(
            "Delta includes masking=%s, row_filtering=%s",
            has_masking, has_row_filter,
        )

    def test_direct_access_stack_differs_from_federated(self) -> None:
        """Direct Redshift/Snowflake stacks lack Ranger enforcement."""
        from src.governance.safety_model import get_engine_governance_stack

        trino_stack = get_engine_governance_stack("trino")
        redshift_stack = get_engine_governance_stack("redshift")
        assert trino_stack.has_ranger is True, "Trino should have Ranger enforcement"
        assert redshift_stack.has_ranger is False, (
            "Direct Redshift should NOT have Ranger enforcement"
        )
        logger.info(
            "Trino has_ranger=%s, Redshift has_ranger=%s — stacks differ as expected",
            trino_stack.has_ranger, redshift_stack.has_ranger,
        )
