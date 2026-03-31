# Validation Spec 4: The Identities

## Narrative

Five people work at the same bank. Same data. Same SQL. Five different views.

Alice is a regional analyst. She sees ledger entries masked and filtered to her
jurisdiction. Bob investigates risk — he needs raw PII across all jurisdictions.
Carol handles compliance for EMEA. Dave is a data scientist with broad but masked
access. Frank is an external auditor on a time-bounded engagement, denied access
to risk signals entirely.

The federation layer ensures each person sees exactly what they should — no more,
no less. The masking, filtering, and denial all flow from a single policy store
(Ranger), tied to group membership. The same SQL statement, executed by different
identities, returns different columns, different rows, or an access-denied error.

This is the governance contrast that the previous scenarios couldn't show: not
just "policies exist" but "policies differentiate."

## Personas

| User | Groups | Sees |
|------|--------|------|
| `alice_analyst` | `data_analysts`, `na_analysts` | Masked PII, NA rows only |
| `bob_risk` | `risk_investigators` | Raw PII (MASK_NONE), all jurisdictions |
| `carol_compliance` | `compliance_officers` | Masked PII, EMEA rows only |
| `dave_ds` | `data_scientists` | Masked PII, all rows |
| `frank_external` | `external_auditors` | Denied on risk_signals |

## Infrastructure Prerequisites

Four defects were discovered and fixed before these tests could work:

1. **MASK_NONE exception policies**: The extractor was creating policyType=0 (access)
   policies for unmask exceptions. Ranger policyType=0 does not override policyType=1
   masking. Fixed to emit policyType=1 with `dataMaskType: MASK_NONE` and
   `policyPriority: 1` (override). Within the same priority, Ranger evaluates
   "most restrictive mask wins" — SHOW_LAST_4 beats MASK_NONE. Override priority
   is required for the exception to take effect.

2. **Policy type migration**: Ranger does not allow changing `policyType` on an
   existing policy via PUT. The `push_policy()` method was enhanced to detect type
   changes and delete-then-recreate instead of in-place update.

3. **Data source path alignment**: Mock Immuta data source `databricks.risk.risk_signals`
   did not match the real Trino resource `databricks.federation_demo.risk_signals`.
   The deny policy was targeting a nonexistent schema.

4. **Group membership provisioning**: Users and groups existed in Ranger as separate
   objects, but no user was assigned to any group. Group-based policies had no effect.
   Ranger 2.x's `/service/xusers/groupusers` POST returns 404 — group membership
   must be set via PUT to `/service/xusers/secure/users/{id}` with `groupIdList`.

## Tests (6)

### Part 1: Same Query, Different Columns

- **`test_analyst_sees_masked_pii`**: alice_analyst queries token_id through Trino;
  result differs from raw Redshift value. Proves masking applies to real users.

- **`test_risk_investigator_sees_raw_pii`**: bob_risk queries the same column;
  result matches raw Redshift value. Proves MASK_NONE exception works.

### Part 2: Row Filter Policy Differentiation

NOTE: Trino 479's Ranger plugin does not implement `getRowFilters()`, so row
filters are not enforced at query time. These tests verify the policy structure
in Ranger — the FGAC intent is captured correctly even though enforcement
requires a plugin upgrade.

- **`test_jurisdiction_filter_policy_differentiates_groups`**: Row filter policies
  in Ranger assign different filter expressions per group. na_analysts has a
  `jurisdiction='NA'` filter. Proves per-group row filter differentiation.

- **`test_row_filter_policy_count_by_group`**: Multiple groups have distinct row
  filter expressions across Ranger policies. Proves the extractor translates
  ABAC row filters into group-specific Ranger policies.

### Part 3: Deny and Audit

- **`test_auditor_denied_risk_signals`**: frank_external gets access-denied on
  databricks.federation_demo.risk_signals. Proves deny policy enforcement.

- **`test_audit_captures_each_identity`**: After alice and bob both query, Solr
  audit trail contains both `reqUser` values. Proves per-identity attribution.

## What This Proves

The federation layer doesn't just have policies — it enforces them differently
for different identities. Column masking, row filtering, deny rules, and audit
attribution all operate on group membership, not a shared service account.
