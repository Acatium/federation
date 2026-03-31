# Validation Spec 2: "The Audit"

## Session Prompt

Paste this into a fresh Claude Code terminal:

```
Read specs/validation-spec-2-the-audit.md and implement it exactly. This is the second of three validation test files. Prerequisites:

1. tests/validation/__init__.py and conftest.py must already exist (created by Spec 1)
2. Verify by running: pytest tests/validation/test_scenario1_the_report.py -v --tb=short (should pass)
3. Implement test_scenario2_the_audit.py with all 23 tests
4. Run pytest tests/validation/test_scenario2_the_audit.py -v --tb=short and fix all failures
5. All tests must be correct — fix errors, do not alter tests unless the test is proven to be inaccurate or ineffective
6. Test results are captured automatically by the results plugin in tests/conftest.py (writes to data/test_results.json) — verify this is working
```

---

## Context

This is a federated data governance reference implementation. Five platforms unified through Gravitino (catalog), Ranger (policy), and Trino (query). Scenario 1 built a counterparty exposure report. Now the auditor arrives: "Where did this number come from? Prove it's accurate. Show me who has access."

Thinking about scenarios where regulatory frameworks like BCBS 239, DORA, and GDPR would apply, this scenario demonstrates that every number traces to its source, every policy has provenance, and every entitlement is visible in one view.

## Existing Infrastructure

### Fixtures from tests/validation/conftest.py (created by Spec 1)

- `solr_audit_url` — `http://{SOLR_HOST}:8983/solr/ranger_audits/select`
- `trino_catalogs` — cached `list[str]` from SHOW CATALOGS
- `entitlement_matrix_df` — Polars DataFrame from EntitlementMatrix
- `gravitino_table_metadata` — structured metadata from Gravitino API walk
- `_reset_redshift_transaction` — autouse rollback

### Fixtures from tests/conftest.py (root — DO NOT MODIFY)

- `trino_conn`, `redshift_conn`, `snowflake_conn` — database connections
- `ranger_policies` — `list[dict]` from Ranger REST API
- `ranger_base_url`, `ranger_auth` — Ranger API access
- `gravitino_base_url`, `gravitino_metalake`, `gravitino_catalogs` — Gravitino API
- `gravitino_model_catalog`, `bedrock_models` — model catalog
- `iceberg_catalog_name` — env `ICEBERG_CATALOG` (default "iceberg_s3")
- `immuta_policies` — `from src.mocks.immuta_mock import POLICIES`

### Src modules

- `src/reports/entitlement_matrix.py` — `EntitlementMatrix`
- `src/mocks/immuta_mock.py` — `POLICIES`, `PERMISSIONS`
- `src/models/bedrock_catalog.py` — `BedrockModelCatalog`, `BEDROCK_MODELS`

## Results Capture

The existing results plugin in `tests/conftest.py` automatically captures per-test logs, duration, and pass/fail status to `data/test_results.json`. This works for ALL test files under `tests/` — no additional setup needed. After running, verify the file contains entries for the new tests.

## What to Create

### `tests/validation/test_scenario2_the_audit.py`

**Module docstring:**
```
"""Scenario 2: The Audit.

The numbers in the counterparty exposure report need to withstand scrutiny.
An auditor asks: where did this number come from? Can you trace it to the
source system? Can you prove it matches the source ledger? Can you show me
who has access and whether controls are in place?

Thinking about scenarios where regulatory frameworks like BCBS 239 (risk
data aggregation accuracy), DORA (operational resilience and audit trails),
and GDPR (data subject rights) would apply, we demonstrate that every
number traces to its source, every policy has provenance, and every
entitlement is visible in one view.
"""
```

**Module-level marker:** `pytestmark = [pytest.mark.validation]`

---

#### Part 1: TestLineage (6 tests)

```python
class TestLineage:
    """Every query leaves a trail. Every policy has provenance."""

    @pytest.mark.slow
    def test_trino_query_produces_solr_audit_event(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """A Trino query generates an audit event in Solr."""
        # 1. Execute a Trino query: SELECT count(*) FROM redshift.federation.ledger_entries
        # 2. Sleep 7 seconds (Solr autoSoftCommit is 5s, add margin)
        # 3. Query Solr: GET {solr_audit_url}?q=*:*&rows=5&sort=evtTime+desc&wt=json
        # 4. Assert response.json()["response"]["numFound"] > 0

    @pytest.mark.slow
    def test_audit_identifies_the_analyst(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """Audit trail records who ran the query."""
        # Query Solr for recent audit events
        # Find an event where reqUser matches the Trino user
        # Assert reqUser == os.getenv("TRINO_USER", "test_user")

    @pytest.mark.slow
    def test_audit_identifies_the_resource(self, solr_audit_url: str) -> None:
        """Audit trail records which resource was queried."""
        # Query Solr for recent events
        # Assert at least one doc has a non-empty "resource" field

    @pytest.mark.slow
    def test_audit_records_authorization_result(self, solr_audit_url: str) -> None:
        """Audit trail records whether access was allowed or denied."""
        # Query Solr for recent events
        # Assert at least one doc has a "result" field (1=allowed, 0=denied)

    def test_policies_trace_to_source_platform(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger policies carry source: labels identifying the originating platform."""
        # Scan policyLabels for "source:" prefixed labels
        # Collect distinct sources (redshift, lake_formation, snowflake, unity_catalog, etc.)
        # Assert >= 3 distinct sources

    def test_policies_carry_extraction_timestamps(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Policies carry extraction_ts: labels for temporal provenance."""
        # Scan policyLabels for "extraction_ts:" prefixed labels
        # Assert >= 1 policy has a timestamp
```

#### Part 2: TestReconciliation (4 tests)

```python
class TestReconciliation:
    """The federated number IS the source number."""

    @pytest.mark.slow
    def test_row_count_matches_source(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """count(*) via Trino equals count(*) via direct Redshift."""
        # Trino: SELECT count(*) FROM redshift.federation.ledger_entries
        # Redshift: SELECT count(*) FROM federation.ledger_entries
        # Assert trino_count == rs_count

    @pytest.mark.slow
    def test_aggregation_matches_source_cent_for_cent(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """Jurisdiction-level SUM(amount) matches between Trino and Redshift."""
        # Trino:
        #   SELECT jurisdiction, CAST(SUM(amount) AS DECIMAL(18,2)) AS total
        #   FROM redshift.federation.ledger_entries
        #   GROUP BY jurisdiction ORDER BY jurisdiction
        # Redshift:
        #   SELECT jurisdiction, CAST(SUM(amount) AS DECIMAL(18,2)) AS total
        #   FROM federation.ledger_entries
        #   GROUP BY jurisdiction ORDER BY jurisdiction
        # Compare: for each jurisdiction, abs(trino_total - rs_total) < 0.01
        # Assert ALL jurisdictions match

    @pytest.mark.slow
    def test_all_source_tables_discoverable(self, trino_conn: Any) -> None:
        """SHOW TABLES FROM redshift.federation includes ledger_entries."""
        # cursor.execute("SHOW TABLES FROM redshift.federation")
        # tables = [row[0] for row in cursor.fetchall()]
        # Assert "ledger_entries" in tables

    @pytest.mark.slow
    def test_schema_matches_source(
        self, trino_conn: Any, redshift_conn: Any
    ) -> None:
        """Column names via Trino match column names via direct Redshift."""
        # Trino: SELECT * FROM redshift.federation.ledger_entries LIMIT 1
        #   → cursor.description → column names
        # Redshift: SELECT * FROM federation.ledger_entries LIMIT 1
        #   → cursor.description → column names
        # Assert column name sets overlap (Trino may have additional metadata columns)
```

#### Part 3: TestUnifiedEntitlements (7 tests)

```python
class TestUnifiedEntitlements:
    """'Who can access counterparty PII?' One query."""

    def test_policies_span_multiple_platforms(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Policies contain source: labels from >= 3 platforms."""
        # Extract all "source:" labels → distinct set
        # Assert len >= 3

    def test_single_api_returns_complete_policy_set(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """One Ranger API call returns all policies."""
        # Assert len(ranger_policies) >= 26

    def test_spectrum_shows_dual_governance(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Both source:redshift and source:lake_formation present."""
        # Extract all source labels
        # Assert "redshift" and "lake_formation" both in sources

    def test_entitlement_matrix_is_cross_platform(
        self, entitlement_matrix_df: pl.DataFrame
    ) -> None:
        """Entitlement matrix covers >= 2 platforms."""
        # Check for "source_system" or "platform" column
        # Assert n_unique >= 2

    def test_masking_policies_identifiable(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=1 masking policies exist."""
        # Filter for policyType == 1
        # Assert len >= 1

    def test_row_filter_policies_identifiable(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=2 row filter policies exist."""
        # Filter for policyType == 2
        # Assert len >= 1

    def test_policies_carry_provenance_labels(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Data-access policies have source: labels."""
        # Count policies with policyType=0 (access) that have a "source:" label
        # Count total access policies
        # Assert >= 80% are labeled (or at least majority)
```

#### Part 4: TestComplianceEvidence (6 tests)

```python
class TestComplianceEvidence:
    """Regulations frame the questions. Tests provide the evidence."""

    def test_masking_policies_enforce_confidentiality(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Masking policies exist for PII columns.

        Relevant where confidentiality requirements (e.g., DORA Art 9) apply.
        """
        # Filter policyType=1 masking policies
        # Check if any reference PII columns (token_id, entity_name, account_ref)
        # Assert >= 1 masking policy

    @pytest.mark.slow
    def test_audit_trail_supports_accountability(
        self, ranger_policies: list[dict[str, Any]], solr_audit_url: str
    ) -> None:
        """Audit trail present and policies are auditable.

        Relevant where audit requirements (e.g., DORA Art 12) apply.
        """
        # Check Ranger policies: all have isAuditEnabled (or most do)
        # Query Solr: numFound > 0
        # Assert both: policies auditable AND audit events exist

    @pytest.mark.slow
    def test_cross_platform_entity_discovery(self, trino_conn: Any) -> None:
        """Find an entity across platforms via one Trino session.

        Relevant where data subject access requirements (e.g., GDPR Art 15) apply.
        """
        # SELECT DISTINCT entity_name FROM redshift.federation.ledger_entries LIMIT 1
        # Take that entity_name
        # SELECT count(*) FROM snowflake.public.entities WHERE entity_name = '{name}'
        # Assert entity discoverable in at least one additional platform (or same platform, different table)

    def test_purpose_controls_defined(self) -> None:
        """Access purposes defined in FGAC layer.

        Relevant where purpose limitation requirements (e.g., GDPR Art 30) apply.
        """
        # from src.mocks.immuta_mock import POLICIES
        # Extract distinct purposes from Immuta policies
        # Assert >= 3 purposes

    def test_model_registry_in_catalog(
        self, bedrock_models: list[dict[str, Any]], gravitino_model_catalog: dict[str, Any]
    ) -> None:
        """Models registered in Gravitino with governance tags.

        Relevant where model inventory requirements (e.g., EU AI Act Art 49) apply.
        """
        # Assert len(bedrock_models) >= 2
        # Assert gravitino_model_catalog is not None
        # Check models have governance_tier property

    def test_segregation_of_duties(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Multiple distinct principals across policy scopes.

        Relevant where separation of duties requirements (e.g., SOX) apply.
        """
        # Extract all users and groups from policyItems across all policies
        # Assert >= 4 distinct principals
```

## Code Standards

Same as Spec 1:
- Python 3.11+, type hints, docstrings, `logging` only, no `print()`
- `pytestmark = [pytest.mark.validation]` at module level
- Slow tests get `@pytest.mark.slow`
- Descriptive assertion messages
- Log key values for evidence capture

## Key Solr Query Pattern

```python
import requests
import time

# After running a Trino query, wait for Solr commit
time.sleep(7)  # autoSoftCommit is 5s, add margin

resp = requests.get(
    solr_audit_url,
    params={"q": "*:*", "rows": 10, "sort": "evtTime desc", "wt": "json"},
    timeout=15,
)
resp.raise_for_status()
data = resp.json()
num_found = data["response"]["numFound"]
docs = data["response"]["docs"]
```

## Key Ranger Policy Structure

```python
# Each policy dict has:
# - "name": str
# - "policyType": 0 (access), 1 (masking), 2 (row filter)
# - "isEnabled": bool
# - "isAuditEnabled": bool
# - "policyLabels": list[str]  — e.g., ["source:redshift", "extraction_ts:2024-01-01T00:00:00"]
# - "resources": dict with "catalog", "schema", "table", "column" keys
# - "policyItems": list[dict] with "users", "groups", "accesses"
```
