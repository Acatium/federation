# Validation Spec 3: "The Failure Modes" + Conclusion

## Session Prompt

Paste this into a fresh Claude Code terminal:

```
Read specs/validation-spec-3-failure-modes.md and implement it exactly. This is the third of three validation test files. Prerequisites:

1. tests/validation/__init__.py and conftest.py must already exist (created by Spec 1)
2. Verify by running: pytest tests/validation/ -v --tb=short (Scenarios 1 and 2 should pass)
3. Implement test_scenario3_the_failure_modes.py with all 27 tests
4. Implement test_conclusion.py with all 11 tests
5. Run pytest tests/validation/ -v --tb=short and fix all failures
6. All tests must be correct — fix errors, do not alter tests unless the test is proven to be inaccurate or ineffective
7. After all tests pass, run: pytest tests/validation/ -v --tb=short and verify all 83 tests pass
8. Check data/test_results.json contains entries for all validation tests (results plugin captures automatically)
9. Verify test results are captured properly — this data feeds the final report
```

---

## Context

This is a federated data governance reference implementation. Five platforms unified through Gravitino (catalog), Ranger (policy), and Trino (query). Scenarios 1 and 2 proved the system works and earns trust. Scenario 3 proves the system fails safely. The conclusion ties the three planes, three access patterns, and honest gaps together.

## Existing Infrastructure

### Fixtures from tests/validation/conftest.py

- `solr_audit_url`, `trino_catalogs`, `entitlement_matrix_df`, `gravitino_table_metadata`, `_reset_redshift_transaction`

### Fixtures from tests/conftest.py (root — DO NOT MODIFY)

- `trino_conn`, `restricted_trino_conn`, `redshift_conn`, `snowflake_conn`
- `ranger_policies`, `ranger_base_url`, `ranger_auth`
- `gravitino_base_url`, `gravitino_metalake`, `gravitino_catalogs`
- `gravitino_model_catalog`, `bedrock_models`, `bedrock_extracted_policies`
- `iceberg_catalog_name`, `s3_bucket`, `aws_region`
- `immuta_policies`, `immuta_permissions`, `immuta_extracted_policies`
- `spark_session`

### Src modules

- `src/governance/safety_model.py`:
  - `EnforcementState` enum: ALLOW, DENY, STALE_ALLOW, STALE_DENY
  - `analyze_sync_gap(ranger_state, platform_state) -> SyncGapOutcome`
  - `SyncGapOutcome` dataclass: access_granted, is_safe, outcome_type, explanation
  - `compute_governance_delta(from_engine, to_engine) -> GovernanceDelta`
  - `get_engine_governance_stack(engine) -> GovernanceStack`
  - `GovernanceStack`: has_masking, has_row_filtering, has_ranger properties
- `src/mocks/immuta_mock.py`: `POLICIES`, `PERMISSIONS`
- `src/extractors/immuta_to_ranger.py`: Immuta→Ranger extractor (for understanding translation)

## Results Capture

The results plugin in `tests/conftest.py` captures per-test evidence to `data/test_results.json`. This includes logs, duration, and pass/fail status. After running, verify the JSON file contains entries for ALL validation tests (scenario 1 + 2 + 3 + conclusion). This data is used for the final report.

## What to Create

### `tests/validation/test_scenario3_the_failure_modes.py`

**Module docstring:**
```
"""Scenario 3: The Failure Modes.

Every system works in the demo. The question an architect — or a
regulator — actually asks is: what happens when it breaks? When the
policy mirror is stale? When someone bypasses the governed path? When
access controls from different platforms conflict?

The answer: the system fails safely. Every failure mode produces a
secure outcome. Every limitation is documented honestly — not hidden.
The sync gap creates noise, not risk. The governed path is the easy
path. And when controls from different systems overlap or conflict,
the result degrades data utility, never data security.
"""
```

**Module-level marker:** `pytestmark = [pytest.mark.validation]`

---

#### Part 1: TestSafeByDefault (5 tests)

```python
class TestSafeByDefault:
    """The sync gap creates noise, not risk."""

    def test_all_sync_gap_quadrants_produce_safe_outcomes(self) -> None:
        """All 4 Ranger×Platform state combinations are safe."""
        # from src.governance.safety_model import (
        #     EnforcementState, analyze_sync_gap
        # )
        # Test all 4 combinations:
        #   (ALLOW, ALLOW) → authorized, is_safe=True
        #   (STALE_ALLOW, DENY) → platform_backstop, is_safe=True
        #   (STALE_DENY, ALLOW) → fail_closed, is_safe=True
        #   (DENY, DENY) → redundant_denial, is_safe=True
        # Assert ALL outcomes have is_safe == True
        # This is COMPUTED, not hardcoded

    def test_stale_allow_blocked_by_platform(self) -> None:
        """Ranger allows (stale) but platform denies → blocked. Platform is backstop."""
        # analyze_sync_gap(STALE_ALLOW, DENY)
        # Assert outcome_type == "platform_backstop"
        # Assert access_granted == False

    def test_stale_deny_blocks_at_federation(self) -> None:
        """Ranger denies (stale) but platform allows → blocked until sync."""
        # analyze_sync_gap(STALE_DENY, ALLOW)
        # Assert outcome_type == "fail_closed"
        # Assert access_granted == False

    @pytest.mark.slow
    def test_unauthorized_user_denied_at_trino(
        self, restricted_trino_conn: Any
    ) -> None:
        """restricted_user gets denied before query reaches source."""
        # Try: SELECT count(*) FROM redshift.federation.ledger_entries
        # Expect exception with "Access Denied" or "CATALOG_NOT_FOUND"
        # Assert the denial happens

    def test_no_policy_grants_everything_to_everyone(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """No Ranger policy grants * to public on * resources."""
        # Scan all policies for:
        #   resources where all values are ["*"]
        #   AND policyItems with groups=["public"] or users=["*"]
        # Assert zero such policies found
```

#### Part 2: TestGovernanceContrast (6 tests)

```python
class TestGovernanceContrast:
    """Same data. Two paths. One governed, one not."""

    @pytest.mark.slow
    def test_governed_path_returns_data(self, trino_conn: Any) -> None:
        """test_user queries via Trino and gets results normally."""
        # SELECT count(*) FROM redshift.federation.ledger_entries
        # Assert count >= 400_000

    @pytest.mark.slow
    def test_pii_masked_through_governed_path(
        self, trino_conn: Any, redshift_conn: Any, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """token_id via Trino vs direct Redshift — same rows, different values.

        The masking is invisible to the analyst but provably present.
        If masking is not active for test_user, fall back to asserting
        masking policies exist (the controls are configured even if the
        specific test user is not in a masked group).
        """
        # Trino: SELECT entry_id, token_id FROM redshift.federation.ledger_entries
        #        ORDER BY entry_id LIMIT 5
        # Redshift: SELECT entry_id, token_id FROM federation.ledger_entries
        #           ORDER BY entry_id LIMIT 5
        # Compare token_id values for matching entry_ids
        # If values differ: PASS (masking is active)
        # If values match: check that policyType=1 masking policies exist
        #   and log a warning that masking may not be active for test_user
        #   but assert masking policies ARE configured

    @pytest.mark.slow
    def test_pii_visible_at_source(self, redshift_conn: Any) -> None:
        """Direct Redshift returns raw token_id — masking is federation-layer."""
        # SELECT token_id FROM federation.ledger_entries LIMIT 5
        # Assert values are non-null, recognizable format (not hashed)
        # Log sample values

    @pytest.mark.slow
    def test_row_filter_constrains_visibility(
        self, trino_conn: Any, redshift_conn: Any, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Trino jurisdictions <= Redshift jurisdictions, or row filter policy exists."""
        # Trino: SELECT DISTINCT jurisdiction FROM redshift.federation.ledger_entries
        # Redshift: SELECT DISTINCT jurisdiction FROM federation.ledger_entries
        # If trino_jurisdictions < rs_jurisdictions: PASS (filtering active)
        # If equal: assert policyType=2 row filter policies exist

    @pytest.mark.slow
    def test_governed_path_generates_audit_trail(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """Trino query produces audit events in Solr."""
        # Execute a Trino query
        # Sleep 7s for Solr commit
        # Query Solr
        # Assert numFound > 0

    @pytest.mark.slow
    def test_ungoverned_path_has_no_federation_audit(
        self, redshift_conn: Any, solr_audit_url: str
    ) -> None:
        """Direct Redshift query does NOT produce Solr audit event."""
        # Note initial Solr count
        # Execute a direct Redshift query
        # Sleep 7s
        # Query Solr again
        # Assert no new events attributable to this direct query
        # (Count may be same or higher from other Trino queries, but
        #  no event should have the direct query's characteristics)
```

#### Part 3: TestFineGrainedControls (7 tests)

```python
class TestFineGrainedControls:
    """Column masking, purpose gates, and honest gaps."""

    def test_immuta_defines_purpose_based_access(self) -> None:
        """Immuta policies specify access purposes."""
        # from src.mocks.immuta_mock import POLICIES
        # Extract distinct purpose values from policies
        # Assert >= 3 purposes (analytics, marketing, compliance, etc.)

    def test_immuta_defines_column_level_masking(self) -> None:
        """Immuta masking rules target specific PII columns."""
        # from src.mocks.immuta_mock import POLICIES
        # Find masking-type policies
        # Extract column names being masked
        # Assert token_id, entity_name, or account_ref are targeted

    def test_abac_to_rbac_translation_is_lossy_and_documented(
        self, immuta_extracted_policies: list[dict[str, Any]]
    ) -> None:
        """Extracted policies carry translation_note labels."""
        # Scan immuta_extracted_policies for policyLabels containing "translation_note:"
        # Assert >= 1 policy has a translation note
        # Log the notes

    def test_every_lossy_translation_is_labeled(
        self, immuta_extracted_policies: list[dict[str, Any]]
    ) -> None:
        """No silent loss — every lossy mapping has an auditable label."""
        # Count policies that came from Immuta (source:immuta label)
        # For each, check it has either translation_note or fidelity label
        # Assert all Immuta-sourced policies are labeled

    def test_double_masking_documented(self) -> None:
        """When Immuta and Ranger both mask same column, overlap is documented."""
        # from src.mocks.immuta_mock import POLICIES
        # Identify columns masked by Immuta (e.g., token_id)
        # This is a known condition: Immuta masks at source, Ranger masks at Trino
        # Document that double masking degrades utility (hash of hash) not security
        # Assert the overlap is knowable from the policy data

    def test_ranger_masking_policies_cover_pii(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=1 masking policies exist for PII columns."""
        # Filter for policyType == 1
        # Assert >= 1
        # Log which columns are covered

    def test_ranger_row_filter_policies_exist(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """policyType=2 row filter policies exist."""
        # Filter for policyType == 2
        # Assert >= 1
```

#### Part 4: TestPlatformEvolution (6 tests)

```python
class TestPlatformEvolution:
    """We added Databricks. Nothing else changed."""

    def test_new_platform_registered_in_catalog(
        self, gravitino_catalogs: list[str]
    ) -> None:
        """Databricks catalog present in Gravitino metalake."""
        # Assert "databricks" in gravitino_catalogs (or similar name)

    def test_new_platform_policies_in_ranger(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """At least one policy with source:unity_catalog label."""
        # Scan policyLabels for "source:unity_catalog"
        # Assert >= 1 found

    @pytest.mark.slow
    def test_redshift_unaffected(self, trino_conn: Any) -> None:
        """500K+ rows still queryable from Redshift."""
        # SELECT count(*) FROM redshift.federation.ledger_entries
        # Assert count >= 400_000

    @pytest.mark.slow
    def test_snowflake_unaffected(self, trino_conn: Any) -> None:
        """Snowflake entities still queryable."""
        # SELECT count(*) FROM snowflake.public.entities
        # Assert count > 0

    @pytest.mark.slow
    def test_iceberg_unaffected(
        self, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Iceberg cold tier still queryable."""
        # SELECT count(*) FROM {iceberg_catalog_name}.federation_demo.ledger_entries_cold
        # Assert count > 0

    def test_prior_policies_intact(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger policies >= 26, prior sources still present."""
        # Assert len >= 26
        # Extract source labels
        # Assert "redshift", "lake_formation", "snowflake" all present
```

#### Part 5: TestEngineGovernanceDelta (3 tests)

```python
class TestEngineGovernanceDelta:
    """Every engine is governed. The stacks differ. The delta is documented."""

    def test_every_engine_has_at_least_two_controls(self) -> None:
        """Governance stacks for each engine have >= 2 controls."""
        # from src.governance.safety_model import get_engine_governance_stack
        # For each engine in ["trino", "spark", "redshift", "snowflake"]:
        #   stack = get_engine_governance_stack(engine)
        #   assert len(stack.controls) >= 2, f"{engine} has < 2 controls"

    def test_trino_vs_spark_governance_delta(self) -> None:
        """compute_governance_delta() shows Trino has masking/filtering Spark lacks."""
        # from src.governance.safety_model import compute_governance_delta
        # delta = compute_governance_delta("trino", "spark")
        # Assert delta is non-empty
        # Log what Trino has that Spark lacks (expected: Ranger masking, row filtering)

    def test_direct_access_stack_differs_from_federated(self) -> None:
        """Direct Redshift/Snowflake stacks lack Ranger enforcement."""
        # from src.governance.safety_model import get_engine_governance_stack
        # trino_stack = get_engine_governance_stack("trino")
        # redshift_stack = get_engine_governance_stack("redshift")
        # Assert trino_stack.has_ranger == True (or similar)
        # Assert redshift_stack.has_ranger == False (or similar)
        # The stacks should differ
```

**Scenario 3 total: 27 tests**

---

### `tests/validation/test_conclusion.py`

**Module docstring:**
```
"""Conclusion: The Architecture.

Three scenarios proved the system works, earns trust, and fails safely.
This conclusion ties the threads: three independent planes that absorb
change, three access patterns that each enforce governance, decoupled
integration cost, and every limitation documented honestly.

The federation layer sits above existing platforms. It replaces nothing.
"""
```

**Module-level marker:** `pytestmark = [pytest.mark.validation]`

---

#### TestThreePlanes (3 tests)

```python
class TestThreePlanes:
    """Metadata, Policy, Query — three independent planes."""

    def test_metadata_plane(
        self, gravitino_metalake: dict[str, Any], gravitino_catalogs: list[str]
    ) -> None:
        """Gravitino provides the metadata plane."""
        # Assert metalake exists
        # Assert >= 5 catalogs

    def test_policy_plane(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Ranger provides the policy plane."""
        # Assert >= 26 policies
        # Assert >= 3 distinct source labels

    def test_query_plane(self, trino_catalogs: list[str]) -> None:
        """Trino provides the query plane."""
        # Assert >= 5 catalogs in SHOW CATALOGS
```

#### TestThreeAccessPatterns (3 tests)

```python
class TestThreeAccessPatterns:
    """Discover, Query, Access — each independently governed."""

    def test_discover_pattern(
        self, gravitino_table_metadata: dict[str, Any]
    ) -> None:
        """Gravitino API returns tables with governance tags."""
        # Assert tables discoverable in metadata
        # Assert at least one catalog has governance_tier property

    @pytest.mark.slow
    def test_query_pattern(
        self, trino_conn: Any, solr_audit_url: str
    ) -> None:
        """Trino executes governed SQL with audit trail."""
        # Execute a query
        # Sleep 7s
        # Verify audit in Solr
        # Assert both: query succeeds AND audit generated

    def test_access_pattern_credential_vending(
        self, gravitino_catalogs: list[str]
    ) -> None:
        """Databricks uses credential vending (the Access pattern)."""
        # Assert "databricks" in gravitino_catalogs
        # Note: the Databricks Trino catalog is configured with
        # iceberg.rest-catalog.vended-credentials-enabled=true
        # This test documents the Access pattern exists
```

#### TestDecoupledCost (2 tests)

```python
class TestDecoupledCost:
    """Adding a platform is an event, not a project."""

    def test_new_platform_didnt_change_existing_policies(
        self, ranger_policies: list[dict[str, Any]]
    ) -> None:
        """Prior sources still present after Databricks addition."""
        # Extract source labels
        # Assert "redshift", "lake_formation", "snowflake" all present

    @pytest.mark.slow
    def test_new_platform_didnt_change_existing_queries(
        self, trino_conn: Any, iceberg_catalog_name: str
    ) -> None:
        """Redshift, Snowflake, Iceberg all still queryable."""
        # Query each, assert > 0 rows
```

#### TestHonestGaps (3 tests)

```python
class TestHonestGaps:
    """Every gap is operational, not architectural."""

    def test_identity_is_local_not_enterprise(self) -> None:
        """Documents: test_user is local, not AD/LDAP."""
        # trino_user = os.getenv("TRINO_USER", "test_user")
        # Assert it's a simple local user name (no @domain)
        # Log: "Identity integration gap: local users, not enterprise AD/LDAP"

    def test_immuta_enforcement_is_mock_only(self) -> None:
        """Immuta extraction works, live enforcement deferred."""
        # from src.mocks.immuta_mock import POLICIES
        # Assert POLICIES is non-empty (extraction/translation works)
        # Log: "Immuta FGAC: extraction tested, live enforcement deferred to production"

    def test_all_gaps_are_operational_not_architectural(self) -> None:
        """Every documented gap is closable with investment, not redesign."""
        # Define the known gaps:
        gaps = [
            {"name": "Identity", "type": "operational", "fix": "AD/LDAP integration"},
            {"name": "Ranger HA", "type": "operational", "fix": "Active-passive pair"},
            {"name": "Immuta FGAC", "type": "integration", "fix": "Live Immuta deployment"},
            {"name": "TLS", "type": "operational", "fix": "TLS everywhere + Vault"},
        ]
        # Assert all gaps have type "operational" or "integration" (not "architectural")
        # Log each gap and its fix
```

**Conclusion total: 11 tests**

---

## Grand Total Across All Specs

| File | Tests |
|------|-------|
| test_scenario1_the_report.py (Spec 1) | 22 |
| test_scenario2_the_audit.py (Spec 2) | 23 |
| test_scenario3_the_failure_modes.py (Spec 3) | 27 |
| test_conclusion.py (Spec 3) | 11 |
| **TOTAL** | **83** |

## Code Standards

Same as Specs 1 and 2:
- Python 3.11+, type hints, docstrings, `logging` only, no `print()`
- `pytestmark = [pytest.mark.validation]` at module level
- Slow tests get `@pytest.mark.slow`
- Descriptive assertion messages
- Log key values for evidence capture
- Results plugin captures to `data/test_results.json` automatically

## Final Verification

After all three specs are implemented:

```bash
# Run the full validation suite
pytest tests/validation/ -v --tb=short

# Verify all 83 tests pass
# Verify data/test_results.json has entries for all validation tests

# Run alongside existing tests (should not conflict)
pytest tests/ -v --tb=short
```
