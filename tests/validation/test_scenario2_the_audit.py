"""Scenario 2: The Audit.

The numbers in the counterparty exposure report need to withstand scrutiny.
An auditor asks: where did this number come from? Can you prove it matches
the source ledger? Can you show me who has access and whether controls are
in place?

We demonstrate three things:

1. **Numeric fidelity.** The federated number IS the source number —
   row counts and jurisdiction-level aggregations match cent-for-cent
   between Trino and direct Redshift.

2. **Query-level audit trail.** Every Trino query produces an immutable
   audit event in Solr with who (reqUser), what (resource), when (evtTime),
   and authorization result. Policies carry source-platform labels and
   extraction timestamps for provenance.

3. **Unified entitlement view.** One Ranger API call returns all policies
   across all platforms — access, masking, and row filter — so the auditor
   can see who has access to what from a single pane.

Limitations (extensible, not architectural):

- This is **query-level** audit, not report-level. There is no correlation
  ID tying a specific report output to the specific queries that produced it.
  A production system would add a report_id to Trino session properties.
- Ranger policies are **point-in-time**, not versioned. You can see current
  policy state and when it was last extracted, but not what the policy looked
  like when a past report was generated. Policy versioning (e.g., Ranger +
  Git-based policy-as-code) would close this gap.
- Solr events support time-range queries, but we test event presence, not
  temporal reconstruction. A production deployment would build time-series
  dashboards over the Solr audit index.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import polars as pl
import pytest
import requests

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.validation]


# ---------------------------------------------------------------------------
# Part 1: TestLineage
# ---------------------------------------------------------------------------


class TestLineage:
    """Every query leaves a trail. Every policy has provenance."""

    @pytest.mark.slow
    def test_trino_query_produces_solr_audit_event(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """A Trino query generates an audit event in Solr."""
        cursor = trino_conn.cursor()
        cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
        count = cursor.fetchone()[0]
        logger.info("Trino ledger_entries count: %d", count)

        # Wait for Solr autoSoftCommit (5s) + margin
        time.sleep(7)

        resp = requests.get(
            solr_audit_url,
            params={"q": "*:*", "rows": 5, "sort": "evtTime desc", "wt": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        num_found = data["response"]["numFound"]
        logger.info("Solr audit events found: %d", num_found)
        assert num_found > 0, "Expected Solr to contain audit events after Trino query"

    @pytest.mark.slow
    def test_audit_identifies_the_analyst(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """Audit trail records who ran the query."""
        # Ensure there's a recent query
        cursor = trino_conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        time.sleep(7)

        resp = requests.get(
            solr_audit_url,
            params={"q": "*:*", "rows": 20, "sort": "evtTime desc", "wt": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        docs = resp.json()["response"]["docs"]

        expected_user = os.getenv("TRINO_USER", "test_user")
        users_found: set[str] = set()
        for doc in docs:
            req_user = doc.get("reqUser", "")
            # Solr may return multi-valued fields as lists
            if isinstance(req_user, list):
                users_found.update(req_user)
            elif req_user:
                users_found.add(req_user)
        logger.info("Audit users found: %s (expected: %s)", users_found, expected_user)
        assert expected_user in users_found, (
            f"Expected reqUser={expected_user} in audit docs, found {users_found}"
        )

    @pytest.mark.slow
    def test_audit_identifies_the_resource(self, solr_audit_url: str) -> None:
        """Audit trail records which resource was queried."""
        resp = requests.get(
            solr_audit_url,
            params={"q": "*:*", "rows": 20, "sort": "evtTime desc", "wt": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        docs = resp.json()["response"]["docs"]

        resources = [doc.get("resource", "") for doc in docs if doc.get("resource")]
        logger.info("Audit resources (sample): %s", resources[:5])
        assert len(resources) > 0, "Expected at least one audit doc with a non-empty resource"

    @pytest.mark.slow
    def test_audit_records_authorization_result(self, solr_audit_url: str) -> None:
        """Audit trail records whether access was allowed or denied."""
        resp = requests.get(
            solr_audit_url,
            params={"q": "*:*", "rows": 20, "sort": "evtTime desc", "wt": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        docs = resp.json()["response"]["docs"]

        docs_with_result = [doc for doc in docs if "result" in doc]
        logger.info(
            "Docs with authorization result: %d/%d", len(docs_with_result), len(docs)
        )
        assert len(docs_with_result) > 0, (
            "Expected at least one audit doc with a 'result' field (1=allowed, 0=denied)"
        )

    def test_policies_trace_to_source_platform(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger policies carry source: labels identifying the originating platform."""
        sources: set[str] = set()
        for policy in ranger_policies:
            for label in policy.get("policyLabels", []):
                if label.startswith("source:"):
                    sources.add(label[len("source:"):])

        logger.info("Distinct policy sources: %s", sorted(sources))
        assert len(sources) >= 3, (
            f"Expected >= 3 distinct source platforms in policy labels, found {sorted(sources)}"
        )

    def test_policies_carry_extraction_timestamps(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Policies carry extraction_ts: labels for temporal provenance.

        Mirrors test_policies_carry_provenance_labels: excludes system/infra
        policies (which have no labels by design) and asserts >= 80% of
        extractor-produced policies carry extraction_ts: labels.
        """
        # Only count extractor-produced policies (those with any labels)
        extracted_policies = [
            p for p in ranger_policies if p.get("policyLabels")
        ]
        policies_with_ts = [
            p for p in extracted_policies
            if any(label.startswith("extraction_ts:") for label in p.get("policyLabels", []))
        ]
        total = len(extracted_policies)
        ts_count = len(policies_with_ts)
        pct = (ts_count / total * 100) if total > 0 else 0.0

        logger.info(
            "Policies with extraction_ts: %d/%d (%.1f%%)",
            ts_count, total, pct,
        )
        assert ts_count >= total * 0.8, (
            f"Expected >= 80%% of extracted policies to carry extraction_ts: labels, "
            f"got {ts_count}/{total} ({pct:.1f}%%)"
        )


# ---------------------------------------------------------------------------
# Part 2: TestReconciliation
# ---------------------------------------------------------------------------


class TestReconciliation:
    """The federated number IS the source number."""

    @pytest.mark.slow
    def test_row_count_matches_source(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """count(*) via Trino equals count(*) via direct Redshift."""
        trino_cursor = trino_conn.cursor()
        trino_cursor.execute("SELECT count(*) FROM redshift.federation.ledger_entries")
        trino_count = trino_cursor.fetchone()[0]

        rs_cursor = redshift_conn.cursor()
        rs_cursor.execute("SELECT count(*) FROM federation.ledger_entries")
        rs_count = rs_cursor.fetchone()[0]

        logger.info("Row counts — Trino: %d, Redshift: %d", trino_count, rs_count)
        assert trino_count == rs_count, (
            f"Trino count ({trino_count}) != Redshift count ({rs_count})"
        )

    @pytest.mark.slow
    def test_aggregation_matches_source_cent_for_cent(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """Jurisdiction-level SUM(amount) matches between Trino and Redshift."""
        trino_cursor = trino_conn.cursor()
        trino_cursor.execute(
            "SELECT jurisdiction, CAST(SUM(amount) AS DECIMAL(18,2)) AS total "
            "FROM redshift.federation.ledger_entries "
            "GROUP BY jurisdiction ORDER BY jurisdiction"
        )
        trino_rows = {row[0]: float(row[1]) for row in trino_cursor.fetchall()}

        rs_cursor = redshift_conn.cursor()
        rs_cursor.execute(
            "SELECT jurisdiction, CAST(SUM(amount) AS DECIMAL(18,2)) AS total "
            "FROM federation.ledger_entries "
            "GROUP BY jurisdiction ORDER BY jurisdiction"
        )
        rs_rows = {row[0]: float(row[1]) for row in rs_cursor.fetchall()}

        logger.info("Trino jurisdictions: %s", trino_rows)
        logger.info("Redshift jurisdictions: %s", rs_rows)

        mismatches: list[str] = []
        for jurisdiction in trino_rows:
            if jurisdiction not in rs_rows:
                mismatches.append(f"{jurisdiction}: missing from Redshift")
            elif abs(trino_rows[jurisdiction] - rs_rows[jurisdiction]) >= 0.01:
                mismatches.append(
                    f"{jurisdiction}: Trino={trino_rows[jurisdiction]}, "
                    f"Redshift={rs_rows[jurisdiction]}"
                )

        assert len(mismatches) == 0, (
            f"Jurisdiction aggregation mismatches: {mismatches}"
        )

    @pytest.mark.slow
    def test_all_source_tables_discoverable(self, trino_conn: Any) -> None:
        """SHOW TABLES FROM redshift.federation includes ledger_entries."""
        cursor = trino_conn.cursor()
        cursor.execute("SHOW TABLES FROM redshift.federation")
        tables = [row[0] for row in cursor.fetchall()]
        logger.info("Tables in redshift.federation: %s", tables)
        assert "ledger_entries" in tables, (
            f"Expected 'ledger_entries' in redshift.federation tables, found {tables}"
        )

    @pytest.mark.slow
    def test_schema_matches_source(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """Column names via Trino match column names via direct Redshift."""
        trino_cursor = trino_conn.cursor()
        trino_cursor.execute(
            "SELECT * FROM redshift.federation.ledger_entries LIMIT 1"
        )
        trino_cursor.fetchall()
        trino_cols = {desc[0] for desc in trino_cursor.description}

        rs_cursor = redshift_conn.cursor()
        rs_cursor.execute("SELECT * FROM federation.ledger_entries LIMIT 1")
        rs_cursor.fetchall()
        rs_cols = {desc[0] for desc in rs_cursor.description}

        logger.info("Trino columns: %s", sorted(trino_cols))
        logger.info("Redshift columns: %s", sorted(rs_cols))

        # Redshift columns should be subset of Trino columns (Trino may add metadata)
        missing = rs_cols - trino_cols
        assert len(missing) == 0, (
            f"Redshift columns missing from Trino: {missing}"
        )


# ---------------------------------------------------------------------------
# Part 3: TestUnifiedEntitlements
# ---------------------------------------------------------------------------


class TestUnifiedEntitlements:
    """'Who can access counterparty PII?' One query."""

    def test_policies_span_multiple_platforms(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Every platform has policies across multiple policy types.

        Distinct from test_policies_trace_to_source_platform (which checks
        source label presence). This verifies each platform contributes
        to the unified entitlement view with substantive policy content,
        not just a label.
        """
        # Build source -> set of policy types
        source_policy_types: dict[str, set[int]] = {}
        for policy in ranger_policies:
            pt = policy.get("policyType", 0)
            for label in policy.get("policyLabels", []):
                if label.startswith("source:"):
                    source = label[len("source:"):]
                    source_policy_types.setdefault(source, set()).add(pt)

        assert len(source_policy_types) >= 3, (
            f"Expected >= 3 platforms, found {sorted(source_policy_types.keys())}"
        )
        # At least one source should have more than just access policies
        sources_with_fgac = [
            s for s, types in source_policy_types.items() if len(types) > 1
        ]
        assert len(sources_with_fgac) >= 1, (
            f"Expected >= 1 platform with multiple policy types (access + masking/filter), "
            f"found: {source_policy_types}"
        )
        for source, types in sorted(source_policy_types.items()):
            logger.info("  %s: policy types %s", source, sorted(types))

    def test_single_api_returns_complete_policy_set(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """One Ranger API call returns all policies."""
        count = len(ranger_policies)
        logger.info("Total Ranger policies from single API call: %d", count)
        assert count >= 26, (
            f"Expected >= 26 policies from Ranger, got {count}"
        )

    def test_spectrum_shows_dual_governance(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Both source:redshift and source:lake_formation present."""
        sources: set[str] = set()
        for policy in ranger_policies:
            for label in policy.get("policyLabels", []):
                if label.startswith("source:"):
                    sources.add(label[len("source:"):])

        logger.info("All source labels: %s", sorted(sources))
        assert "redshift" in sources, (
            f"Expected 'redshift' in source labels, found {sorted(sources)}"
        )
        assert "lake_formation" in sources, (
            f"Expected 'lake_formation' in source labels, found {sorted(sources)}"
        )

    def test_entitlement_matrix_is_cross_platform(
        self, entitlement_matrix_df: pl.DataFrame
    ) -> None:
        """Entitlement matrix covers >= 2 platforms."""
        # Check for platform or source_system column
        if "platform" in entitlement_matrix_df.columns:
            col = "platform"
        elif "source_system" in entitlement_matrix_df.columns:
            col = "source_system"
        else:
            pytest.fail(
                f"Expected 'platform' or 'source_system' column, "
                f"found {entitlement_matrix_df.columns}"
            )

        unique_platforms = entitlement_matrix_df[col].n_unique()
        platform_values = entitlement_matrix_df[col].unique().to_list()
        logger.info(
            "Entitlement matrix %s values (%d unique): %s",
            col,
            unique_platforms,
            platform_values,
        )
        assert unique_platforms >= 2, (
            f"Expected >= 2 unique platforms in entitlement matrix, "
            f"found {platform_values}"
        )

    def test_masking_policies_identifiable(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=1 masking policies exist."""
        masking = [p for p in ranger_policies if p.get("policyType") == 1]
        logger.info("Masking policies (policyType=1): %d", len(masking))
        assert len(masking) >= 1, (
            "Expected >= 1 masking policy (policyType=1)"
        )

    def test_row_filter_policies_identifiable(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=2 row filter policies exist."""
        row_filters = [p for p in ranger_policies if p.get("policyType") == 2]
        logger.info("Row filter policies (policyType=2): %d", len(row_filters))
        assert len(row_filters) >= 1, (
            "Expected >= 1 row filter policy (policyType=2)"
        )

    def test_policies_carry_provenance_labels(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Data-access policies have source: labels.

        Excludes Ranger system/infrastructure policies (which have no labels
        by design) — only extractor-produced governance policies are counted.
        """
        access_policies = [
            p for p in ranger_policies
            if p.get("policyType", 0) == 0 and p.get("policyLabels")
        ]
        labeled = [
            p for p in access_policies
            if any(label.startswith("source:") for label in p.get("policyLabels", []))
        ]
        total = len(access_policies)
        labeled_count = len(labeled)
        pct = (labeled_count / total * 100) if total > 0 else 0.0

        logger.info(
            "Access policies with source: labels: %d/%d (%.1f%%)",
            labeled_count,
            total,
            pct,
        )
        assert labeled_count >= total * 0.8, (
            f"Expected >= 80%% of access policies to carry source: labels, "
            f"got {labeled_count}/{total} ({pct:.1f}%%)"
        )


# ---------------------------------------------------------------------------
# Part 4: TestComplianceEvidence
# ---------------------------------------------------------------------------


class TestComplianceEvidence:
    """The controls an auditor would look for — demonstrated, not claimed."""

    def test_masking_policies_enforce_confidentiality(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Masking policies exist for PII columns."""
        pii_columns = {"token_id", "entity_name", "account_ref"}
        masking_policies = [p for p in ranger_policies if p.get("policyType") == 1]

        pii_masking: list[str] = []
        for policy in masking_policies:
            resources = policy.get("resources", {})
            columns = resources.get("column", {}).get("values", [])
            if any(col in pii_columns for col in columns):
                pii_masking.append(policy.get("name", ""))

        logger.info("Masking policies referencing PII columns: %s", pii_masking)
        assert len(pii_masking) >= 1, (
            f"Expected >= 1 masking policy targeting PII columns {pii_columns}, "
            f"but {len(masking_policies)} masking policies target other columns"
        )

    @pytest.mark.slow
    def test_audit_trail_supports_accountability(
        self, ranger_policies: list[dict[str, Any]], solr_audit_url: str
    ) -> None:
        """Audit trail present and policies are auditable."""
        # Check policies are audit-enabled
        auditable = [p for p in ranger_policies if p.get("isAuditEnabled", False)]
        logger.info(
            "Audit-enabled policies: %d/%d", len(auditable), len(ranger_policies)
        )

        # Check Solr has audit events
        resp = requests.get(
            solr_audit_url,
            params={"q": "*:*", "rows": 1, "wt": "json"},
            timeout=15,
        )
        resp.raise_for_status()
        num_found = resp.json()["response"]["numFound"]
        logger.info("Solr audit events: %d", num_found)

        assert len(auditable) > 0, "Expected audit-enabled policies in Ranger"
        assert num_found > 0, "Expected audit events in Solr"

    @pytest.mark.slow
    def test_cross_platform_entity_discovery(self, trino_conn: Any) -> None:
        """Find common dimensions across platforms via one Trino session.

        A single Trino session can search for shared jurisdictions across
        Redshift and Snowflake without switching connections. Note: PII
        fields (entity_name) are masked by Ranger, so cross-platform
        discovery uses non-PII keys like jurisdiction. Per-entity lookup
        across platforms would require unmasked access or platform-level
        search.
        """
        cursor = trino_conn.cursor()

        # Get jurisdictions from both platforms and verify overlap
        # (entity_name may be masked by Ranger, so use jurisdiction as the
        # cross-platform key — it's non-PII and not subject to masking)
        cursor.execute(
            "SELECT DISTINCT jurisdiction "
            "FROM redshift.federation.ledger_entries"
        )
        rs_jurisdictions = {row[0] for row in cursor.fetchall()}
        assert len(rs_jurisdictions) > 0, "No jurisdictions in Redshift ledger"
        logger.info("Redshift jurisdictions: %s", sorted(rs_jurisdictions))

        cursor.execute(
            "SELECT DISTINCT jurisdiction FROM snowflake.public.entities"
        )
        sf_jurisdictions = {row[0] for row in cursor.fetchall()}
        assert len(sf_jurisdictions) > 0, "No jurisdictions in Snowflake entities"
        logger.info("Snowflake jurisdictions: %s", sorted(sf_jurisdictions))

        # Cross-platform discovery: same jurisdictions appear in both systems
        overlap = rs_jurisdictions & sf_jurisdictions
        assert len(overlap) > 0, (
            f"Expected jurisdiction overlap between Redshift and Snowflake. "
            f"Redshift: {sorted(rs_jurisdictions)}, "
            f"Snowflake: {sorted(sf_jurisdictions)}"
        )
        logger.info(
            "Cross-platform entity discovery: %d shared jurisdictions (%s) "
            "found via single Trino session",
            len(overlap), sorted(overlap),
        )

    def test_purpose_controls_defined(self) -> None:
        """Immuta mock defines distinct access purposes for the FGAC layer.

        Tests Immuta mock policy structure (src/mocks/immuta_mock.py) — no
        live Immuta instance is contacted. Proves the extraction pipeline
        handles purpose-based access structures (e.g., general_analytics,
        risk_investigation, external_audit). In production, these gate who
        can access what data and why.
        """
        from src.mocks.immuta_mock import POLICIES

        purposes: set[str] = set()
        for policy in POLICIES:
            purpose = policy.get("purpose", "")
            if purpose:
                purposes.add(purpose)

        logger.info("Immuta purposes: %s", sorted(purposes))
        assert len(purposes) >= 3, (
            f"Expected >= 3 distinct purposes in Immuta policies, found {sorted(purposes)}"
        )

    def test_model_registry_in_catalog(
        self, bedrock_models: list[dict[str, Any]], gravitino_model_catalog: dict[str, Any]
    ) -> None:
        """Models registered in Gravitino with governance tags.

        AI models live in the same catalog as data assets, with the same
        governance tagging. This demonstrates that the metadata plane
        extends to models, not just tables.
        """
        logger.info("Bedrock models count: %d", len(bedrock_models))
        logger.info("Gravitino model catalog: %s", gravitino_model_catalog)

        assert len(bedrock_models) >= 2, (
            f"Expected >= 2 Bedrock models, got {len(bedrock_models)}"
        )
        # Verify catalog has MODEL type (not just any dict)
        cat_type = gravitino_model_catalog.get("type", "")
        if not cat_type:
            # Gravitino wraps in {"catalog": {...}}
            cat_type = gravitino_model_catalog.get("catalog", {}).get("type", "")
        assert cat_type.upper() == "MODEL", (
            f"Expected catalog type 'MODEL', got '{cat_type}'"
        )

        # Check models have governance_tier property
        models_with_tier = [
            m for m in bedrock_models
            if m.get("properties", {}).get("governance_tier")
        ]
        assert len(models_with_tier) >= 1, (
            f"Expected >= 1 model with governance_tier, got {len(models_with_tier)}"
        )
        logger.info(
            "Models with governance_tier: %d/%d",
            len(models_with_tier),
            len(bedrock_models),
        )

    def test_segregation_of_duties(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Multiple distinct principals across policy scopes.

        Different users and groups have different access levels — not
        everyone can see everything. This is the foundation for separation
        of duties in production.
        """
        principals: set[str] = set()
        for policy in ranger_policies:
            for items_key in ("policyItems", "denyPolicyItems",
                              "dataMaskPolicyItems", "rowFilterPolicyItems"):
                for item in policy.get(items_key, []):
                    for user in item.get("users", []):
                        principals.add(f"user:{user}")
                    for group in item.get("groups", []):
                        principals.add(f"group:{group}")

        logger.info("Distinct principals: %s", sorted(principals))
        assert len(principals) >= 4, (
            f"Expected >= 4 distinct principals for segregation of duties, "
            f"found {sorted(principals)}"
        )
