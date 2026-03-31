# Claims Reference Card

> **Purpose:** What you can say, what you can't, and where the evidence is.
> Every claim traces to a specific test in the 88-test validation suite.

---

## Proven (cite these tests)

### Five-source federation with cent-for-cent numeric fidelity
"We demonstrated five-source federation — Redshift, S3/Iceberg, Snowflake, Databricks Unity Catalog, and AWS Glue — from a single SQL session, with cent-for-cent numeric fidelity between federated and direct-source results."
- **S1:** `test_full_lifecycle_query` (5-leg UNION ALL, all legs > 0 rows)
- **S1:** `test_hot_tier_redshift`, `test_warm_tier_s3_parquet`, `test_cold_tier_iceberg`, `test_counterparty_reference_snowflake`, `test_risk_signals_databricks`
- **S2:** `test_row_count_matches_source` (count == count)
- **S2:** `test_aggregation_matches_source_cent_for_cent` (SUM(amount) matches within 0.01)

### Formalized safety property — all sync-gap combinations are safe by construction
"We formalized the safety property with an exhaustive 16-combination truth table — 4 Ranger states x 4 Platform states. Every combination produces a safe outcome. The sync gap creates noise, not risk."
- **S3:** `test_all_sync_gap_quadrants_produce_safe_outcomes` (16 computed outcomes, all safe)
- **S3:** `test_stale_allow_blocked_by_platform` (platform_backstop)
- **S3:** `test_stale_deny_blocks_at_federation` (fail_closed)
- **S3:** `test_unauthorized_user_denied_at_trino` (live denial)
- **Source:** `src/governance/safety_model.py`

### Per-identity policy differentiation — same SQL, different views
"We proved per-identity masking and denial: same SQL, different results depending on group membership. Five personas with distinct access levels."
- **S4:** `test_analyst_sees_masked_pii` (alice sees masked token_id)
- **S4:** `test_risk_investigator_sees_raw_pii` (bob sees raw token_id)
- **S4:** `test_auditor_denied_risk_signals` (frank gets access denied)
- **S4:** `test_audit_captures_each_identity` (per-identity audit events in Solr)

### Unified entitlement view across 5 platforms
"We unified entitlements from 5 platforms in one Ranger API call, with provenance labels tracing each policy to its source platform and extraction timestamp."
- **S2:** `test_single_api_returns_complete_policy_set` (>= 26 policies from single API)
- **S2:** `test_policies_span_multiple_platforms` (>= 3 platforms with multiple policy types)
- **S2:** `test_spectrum_shows_dual_governance` (both Redshift RBAC + Lake Formation)
- **S2:** `test_policies_carry_provenance_labels` (>= 80% carry source: labels)
- **S2:** `test_policies_carry_extraction_timestamps` (extraction_ts: labels)

### Documented fidelity loss in ABAC-to-RBAC translation
"Every fidelity loss in the ABAC-to-RBAC translation is labeled and auditable — not hidden. This is a novel contribution: transparent loss documentation rather than silent degradation."
- **S3:** `test_abac_to_rbac_translation_is_lossy_and_documented` (translation_note: labels)
- **S3:** `test_every_lossy_translation_is_labeled` (100% of Immuta-sourced policies labeled)

### Platform-additive architecture
"Adding Databricks (the fifth platform) didn't change any existing policies or query results. Adding a platform is an event, not a project."
- **S3:** `test_new_platform_registered_in_catalog`, `test_new_platform_policies_in_ranger`, `test_redshift_unaffected`, `test_snowflake_unaffected`, `test_iceberg_unaffected`, `test_prior_policies_intact`
- **Conclusion:** `test_new_platform_didnt_change_existing_policies`, `test_new_platform_didnt_change_existing_queries`

### Query-level audit trail
"Every governed query produces an immutable audit event in Solr with user identity, resource, and authorization result."
- **S2:** `test_trino_query_produces_solr_audit_event`, `test_audit_identifies_the_analyst`, `test_audit_identifies_the_resource`, `test_audit_records_authorization_result`
- **S3:** `test_governed_path_generates_audit_trail`, `test_ungoverned_path_has_no_federation_audit`

---

## Demonstrated but limited (cite tests + limitations)

### Masking policies configured and verified for specific personas
"Masking policies are configured in Ranger and verified for specific personas (S4). Enforcement depends on user-group targeting — policy existence is the minimum provable claim for generic users."
- **S3:** `test_pii_masked_through_governed_path` (masking active OR policies exist)
- **S4:** `test_analyst_sees_masked_pii`, `test_risk_investigator_sees_raw_pii` (hard equality/inequality for specific personas)
- **Limitation:** For test_user (generic), masking enforcement depends on group membership. S4 proves differentiation for specific personas.

### Row filter policies differentiate groups; runtime enforcement deferred
"Row filter policies exist in Ranger and correctly differentiate between groups (na_analysts restricted, risk_investigators exempt). Runtime enforcement requires a Ranger plugin update."
- **S4:** `test_jurisdiction_filter_policy_differentiates_groups`, `test_row_filter_policy_count_by_group`
- **S3:** `test_row_filter_constrains_visibility` (row filter policies exist)
- **Limitation:** Trino 479 Ranger plugin lacks `getRowFilters()`. Policies are proven to differentiate, enforcement is deferred.

### LLM generates cross-platform SQL from metadata context
"Snowflake Cortex generates valid cross-platform SQL from Gravitino metadata context. The chain (metadata → LLM → SQL referencing correct catalogs) is the proof point; execution is non-deterministic."
- **S1:** `test_cortex_writes_the_query` (chain proven, execution best-effort)
- **S1:** `test_cortex_responds` (Cortex callable)
- **Limitation:** LLM output is non-deterministic; execution may fail. The chain itself is the contribution.

### Immuta FGAC extraction pipeline
"The Immuta extraction pipeline correctly translates purpose-based access, column masking, and row filtering into Ranger-format policies with fidelity labels. Live enforcement is tested against deterministic mock data."
- **S3:** `test_immuta_defines_purpose_based_access`, `test_immuta_defines_column_level_masking`
- **S2:** `test_purpose_controls_defined`
- **Limitation:** Uses deterministic mock (`src/mocks/immuta_mock.py`), not a live Immuta instance. Proves extraction pipeline, not enforcement.

---

## Not proven (honest gaps — do not claim)

| Gap | Reality | Path to Close |
|-----|---------|--------------|
| **Enterprise identity integration** | Uses 5 local Trino personas with file-based group provider, not AD/LDAP/SAML | Configuration change: Ranger UserSync + Trino LDAP authenticator |
| **Immuta live enforcement** | Mock-only extraction pipeline; no live Immuta proxy | Network path changes to insert Immuta proxy inline |
| **Row filter runtime enforcement** | Policies exist and differentiate groups; Trino 479 Ranger plugin lacks `getRowFilters()` | Plugin update or Ranger version upgrade |
| **High availability** | Single-instance Ranger Admin and Gravitino | Ranger HA (native), Gravitino backend → RDS Multi-AZ |
| **TLS in reference deployment** | HTTP on internal Docker network; `.env` for credentials | Standard TLS configuration + Secrets Manager |
| **Report-level audit correlation** | Query-level audit only; no report_id → query correlation | Trino session property injection |
| **Regulatory compliance** | Can describe capabilities relevant to regulatory requirements and demonstrate them with tests; cannot claim compliance | Formal compliance assessment by qualified auditors |
| **Policy versioning** | Point-in-time policy view; no historical policy state | Ranger + Git-based policy-as-code |

---

## Framing Notes

- **"No mocks, no stubs"** — Do NOT say this. The Immuta FGAC layer uses `src/mocks/immuta_mock.py`. Honest framing: "All five data sources use live infrastructure. The Immuta FGAC layer uses deterministic mock data for reproducible testing of the extraction pipeline."
- **Test count** — The canonical validation suite is **88 tests**. Do not reference 271 or 178 (legacy counts from excluded tests).
- **Regulatory claims** — Describe what's demonstrated and how it maps to regulatory requirements. Do not claim compliance.
- **Row filtering** — Say "policies exist and differentiate groups" not "row filtering is enforced at query time."
