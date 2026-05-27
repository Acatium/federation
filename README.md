# Federated Data Governance — Reference Implementation

A reference implementation that **mirrors platform-native data-access policies into a single
canonical store (Apache Ranger)** and queries across **AWS** (Glue, Lake Formation,
Redshift, Spectrum), **Databricks** (Unity Catalog), and **Snowflake** via
[Apache Gravitino](https://gravitino.apache.org/), [Trino](https://trino.io/), and
[Apache Ranger](https://ranger.apache.org/) — so an organization that adopted several data
platforms can get one catalog, one policy view, and one audit trail *above* them without
replacing anything.

> **What this is — read first.** This is a **learn-by-doing AI-engineering experiment**
> exploring federated data governance, not a hardened product. The core code is real
> (~10K LOC of policy extractors + a computed safety model), and a meaningful slice runs and
> is tested **offline**. But the headline end-to-end claims (cross-platform queries,
> regulatory proof-points) require a **6-container Docker stack + live AWS / Snowflake /
> Databricks credentials**, and two of the integrations are deliberately mock/simulated.
> This README states plainly what runs offline vs. what needs infrastructure, and where the
> mocks are — the spirit of the repo's own `TestHonestGaps` class, pulled up front.

---

## What runs offline vs. what needs infrastructure

| Tier | What | Runs without infra? |
|------|------|---------------------|
| **`tests/unit/`** | 82 unit tests — extractor logic, drift detection, sync config, entitlement matrix, the **regulatory *unit* checks**, and the **safe-by-default safety matrix** (`tests/unit/test_safety_model.py`) | **Yes** — no DB, network, or cloud creds. Run in CI. |
| **`tests/positive/`** (UC-1…UC-11) | Catalog/query/Spectrum/enforcement proof-points | **No** — need Trino + Ranger + Gravitino + cloud data |
| **`tests/regulatory/`** | BCBS 239 / DORA / GDPR / SOX-CCAR scenarios | **No** — need the live stack; they `pytest.skip` or **error** without it |
| **`tests/validation/`** (88 tests) | The S1–S4 + conclusion narrative suite | **No** — need the full 6-container stack + cloud creds |
| **`tests/performance/`** | Benchmarks | **No** |

> **Honest note on graceful skipping:** the offline `tests/unit/` suite is clean. The
> `tests/validation/`, `tests/regulatory/`, and `tests/positive/` tiers do **not** all skip
> gracefully on a fresh clone — without the stack, many **error or fail** at fixture setup
> (e.g. when Trino/Ranger/Gravitino are unreachable), they don't merely show as "skipped."
> Treat `tests/unit/` as the only suite that's green without infrastructure.

```bash
# The offline suite (this is what CI runs):
pip install pytest pytest-timeout requests boto3 python-dotenv polars jinja2 \
            faker psycopg2-binary snowflake-connector-python databricks-sdk
pytest tests/unit              # 82 passed

# The full suite needs the stack + credentials:
cp .env.template .env && make setup && make deploy && make provision
make test
```

## What this explores

- **Two-tier governance with no "ungoverned" tier.** Every dataset has Tier 1
  platform-native enforcement (Redshift/Snowflake RBAC, Unity Catalog ACLs, Lake Formation,
  IAM); selected sensitive datasets add Tier 2 fine-grained controls. Ranger **mirrors** all
  of it for unified visibility and audit; the source platforms remain the enforcement
  backstop.

- **A computed "safe-by-default" safety model** (`src/governance/safety_model.py`). Access
  requires *both* Ranger and the platform to allow (logical AND), so a stale Ranger policy
  can create noise but not a data leak: stale-allow is caught by the platform backstop,
  stale-deny fails closed. The model **computes** the outcome for every Ranger×platform
  state rather than asserting it — and `tests/unit/test_safety_model.py` exercises all four
  sync-gap quadrants, the staleness scenarios, and the per-engine governance stacks
  **offline**.

- **Six real policy extractors → one canonical Ranger schema** (`src/extractors/`):
  Lake Formation, Glue/IAM, Redshift, Snowflake, Unity Catalog, and Immuta each normalize
  platform-native policies into Ranger's format, with provenance labels and idempotent
  re-runs. Drift detection compares each run against a saved snapshot and aborts if >50% of
  pushes fail.

- **A unified entitlement matrix** (`src/reports/entitlement_matrix.py`) — one flat,
  cross-platform view of all Ranger policies for audit.

## What I learned

- **Mirror, don't replace.** Making Ranger the canonical *mirror* (not the enforcement
  authority) is what makes the federation layer safe to add on top of existing platforms —
  the platforms stay the backstop, so a sync gap degrades to noise, not risk.

- **Translation loss must be labeled, not hidden.** Immuta's purpose-based ABAC can't be
  fully represented in Ranger's RBAC model; the lossy parts are explicitly labeled and
  tracked rather than silently dropped.

- **Prove safety by computing it.** Hardcoding "the architecture is safe" proves nothing;
  computing the outcome for every enforcement-state combination (and unit-testing it) is
  what makes the claim checkable.

- **Honest gaps beat a polished demo.** The repo keeps a `TestHonestGaps` class
  (`tests/validation/test_conclusion.py`) documenting its own limits — that instinct is the
  right one, and this README pulls it to the front (below).

## Honest gaps (what is *not* fully real here)

Pulled up from `TestHonestGaps` and the `SIMULATION NOTE`s in the code:

- **Immuta is mock-backed.** The extraction pipeline produces valid Ranger-format policies
  end-to-end, but it reads from a mock Immuta API (`src/mocks/immuta_mock.py`); **live Immuta
  enforcement is not wired up** (`TestHonestGaps.test_immuta_enforcement_is_mock_only`).

- **Bedrock and Iceberg "extractors" are simulations.** `src/extractors/bedrock_to_ranger.py`
  and `src/extractors/iceberg_gap_fill.py` are marked `SIMULATION NOTE`: they generate
  deterministic Ranger policies from a known schema rather than reading a live source. The
  Bedrock model catalog (`src/models/bedrock_catalog.py`) returns **simulated** results when
  Gravitino is unreachable. So of the eight extractor classes, **six** read from real
  platform APIs and **two** are deterministic generators.

- **Identity is local, not enterprise.** Tests run as a local Trino user, not AD/LDAP;
  identity *propagation* works, but enterprise SSO integration is operational future work
  (`TestHonestGaps.test_identity_is_local_not_enterprise`).

- **The regulatory proof-points (BCBS 239 / DORA / GDPR / SOX-CCAR) do not run offline.**
  They live in `tests/regulatory/` and `tests/validation/` and require the live stack +
  cloud credentials. The repository previously committed a generated `data/test_results.json`
  showing all 88 validation tests "passed" with **empty log arrays** — that's a capture
  artifact, not standalone evidence, so it (and the generated `reports/federation-report.html`)
  are no longer tracked; they regenerate when you actually run the validation suite against
  the stack via `make test`.

## Architecture

```
DELIVERY    Arrow Flight SQL          governed columnar transport
QUERY       Trino + Ranger            federated SQL + policy enforcement
GOVERNANCE  Ranger                    canonical policy store + unified audit
CATALOG     Gravitino                 federated metadata across all platforms
```

**Safe by default.** Ranger and the platform are independent layers; access needs both
(logical AND):

- **Stale allow** — Ranger permits on outdated policy, but the source platform denies
  natively → failed query, not data leak.
- **Stale deny** — a new grant exists at the platform, but Ranger hasn't synced → user
  blocked until sync. Fail-closed.

> The sync gap creates noise, not risk.

## Policy Extractors

Six extractors read from real platform APIs and normalize into Ranger's canonical schema;
two more are deterministic generators (clearly labeled):

| Extractor | Source | Status |
|-----------|--------|--------|
| `lf_to_ranger` | Lake Formation (`boto3 list_permissions`) | Real |
| `glue_iam_to_ranger` | Glue resource policies + IAM (`GetResourcePolicies` + `SimulatePrincipalPolicy`) | Real |
| `redshift_to_ranger` | Redshift RBAC (`svv_relation_privileges`) | Real |
| `snowflake_to_ranger` | Snowflake RBAC + masking (`SHOW GRANTS`/`SHOW MASKING POLICIES`) | Real |
| `uc_to_ranger` | Unity Catalog (`databricks-sdk` grants API) | Real |
| `immuta_to_ranger` | Immuta ABAC (REST) | Real pipeline, **mock-backed** source |
| `iceberg_gap_fill` | S3 Iceberg cold tier | **Simulated** (deterministic gap-fill) |
| `bedrock_to_ranger` | Bedrock models | **Simulated** (mirror policies) |

Extractors run in priority order, are idempotent, and carry provenance labels (source
system, extraction timestamp, original grant text).

## Project Structure

```
src/
  extractors/   Policy extractors (6 real + 2 simulated → Ranger)
  loaders/      Deterministic test-data generation (seed=42)
  arrow/        Arrow Flight SQL / ADBC connectors and benchmarks
  governance/   safety_model.py — the computed safe-by-default model
  reports/      Entitlement matrix + final report generator
  sync/         Sync intervals, priority ordering, drift-detection config
  models/       Bedrock model catalog integration (simulated when offline)
  mocks/        Mock Immuta API server
  validators/   Contract and build-status validation
  utils/        Shared config and SQL safety

tests/
  unit/         Offline unit tests (82) — incl. the safe-by-default safety matrix
  positive/     UC-1…UC-11 — require the live stack
  regulatory/   BCBS 239, DORA, GDPR, SOX-CCAR, safe-by-default — require the live stack
  validation/   S1–S4 + conclusion narrative suite (88) — require the full stack
  performance/  Benchmarks — require the live stack

deploy/         docker-compose stack + provisioning scripts
notebooks/      Demo notebooks (safe-by-default, spectrum proof-point, governance comparison)
```

## Key Design Decisions

1. **Ranger mirrors, platforms enforce.** Ranger is the canonical policy store for
   visibility and audit; source platforms remain the enforcement backstop.
2. **Lossy translation is documented, not hidden.** Immuta's purpose-based ABAC can't be
   fully represented in Ranger's RBAC model — the semantic loss is labeled and tracked.
3. **Arrow governs at the boundary.** Arrow Flight SQL → Trino is governed; direct S3 Arrow
   reads with static IAM bypass Trino governance — a documented tradeoff
   (`src/governance/safety_model.py` `ARROW_TRANSPORTS`).
4. **Deterministic test data.** Generated data uses `seed=42` for reproducibility.

## License

[Apache License 2.0](LICENSE)
