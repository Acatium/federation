# Federated Data Governance — Reference Implementation

Proves federated metadata, policy, and query execution across **AWS** (Glue, Lake Formation, Redshift, Spectrum), **Databricks** (Unity Catalog), and **Snowflake** using [Apache Gravitino](https://gravitino.apache.org/), [Trino](https://trino.io/), and [Apache Ranger](https://ranger.apache.org/).

## Why Federation?

Organizations that independently adopted multiple data platforms end up with no unified catalog, no cross-platform query, no unified policy view, and no unified audit trail. The federation layer sits **above** existing platforms — it does not replace anything.

## Architecture

```
DELIVERY    Arrow Flight SQL          governed columnar transport
QUERY       Trino + Ranger            federated SQL + policy enforcement
GOVERNANCE  Ranger                    canonical policy store + unified audit
CATALOG     Gravitino                 federated metadata across all platforms
```

### Two-Tier Governance Model

Every dataset has governance. There is no "ungoverned" tier.

| Tier | Mechanism | Scope |
|------|-----------|-------|
| **Tier 1 — Platform-native** | Redshift RBAC, Snowflake RBAC, Unity Catalog ACLs, Lake Formation, IAM | All datasets |
| **Tier 2 — Fine-grained (Immuta)** | Column masking, row filtering, purpose-based ABAC | Selected sensitive datasets |

### Safe by Default

The architecture cannot produce unauthorized data access even when Ranger sync is stale:

- **Stale allow** — Ranger permits based on outdated policy, but the source platform denies natively. Result: failed query, not data leak.
- **Stale deny** — A new grant exists at the platform, but Ranger hasn't synced. Result: user blocked until sync. Fail-closed.

> The sync gap creates noise, not risk.

### Architecture Constraints

- **Trino 479** with direct catalog connectors (Redshift, Snowflake, Hive/Glue, Iceberg/Glue) and built-in Ranger access-control plugin
- **Hive/Iceberg catalogs** use the **AWS Glue Data Catalog** as the metastore (no HMS dependency)
- **Snowflake:** Policies extracted to Ranger, queryable via Trino's native Snowflake connector
- **Databricks:** Policies extracted to Ranger, data federated via S3 Hive path (direct S3 reads)

## Quick Start

### Prerequisites

- Python 3.11+, Docker, Docker Compose v2, AWS CLI configured
- Active accounts: AWS (Glue/Redshift/S3/Lake Formation), Snowflake, Databricks

### Setup

```bash
git clone <repo> && cd federation
cp .env.template .env   # Fill in all credentials
make setup               # Install deps, generate configs, download plugins
```

### Deploy Infrastructure

```bash
make deploy              # Starts 6 Docker containers (Gravitino, Ranger, Trino, MySQL, Postgres, Solr)
make provision           # Registers catalogs, loads data, pushes policies, verifies enforcement
```

### Verify

```bash
make test-unit           # Unit tests (no infrastructure needed)
make test                # Full test suite from host (requires infrastructure)
make test-docker         # Full test suite in container (same Docker network as services)
make verify              # Lint + typecheck + unit tests
```

### Teardown

```bash
make clean               # Stops containers, removes volumes and generated files
```

## Project Structure

```
src/
  extractors/       Policy extractors: LF, Glue/IAM, Redshift, Snowflake, UC, Immuta → Ranger
  loaders/          Deterministic test data generation and loading
  arrow/            Arrow Flight SQL / ADBC connectors and benchmarks
  reports/          Unified entitlement matrix and policy reports
  sync/             Sync intervals, priority ordering, drift detection config
  models/           Bedrock model catalog integration
  mocks/            Mock Immuta API server
  validators/       Contract and build status validation
  utils/            Shared configuration and SQL safety

tests/
  unit/             Unit tests (no infrastructure required)
  positive/         UC-1 through UC-11 (catalog, query, policy, Spectrum, AI, Arrow, enforcement)
  negative/         NEG-1 through NEG-10 (stale sync, double masking, bypass, drift, etc.)
  regulatory/       BCBS 239, DORA, EU AI Act, GDPR, SOX/CCAR, safe-by-default
  arrow/            Arrow path comparison and benchmark tests

notebooks/
  safe-by-default.ipynb          Live revoke-at-source demo
  spectrum-proof-point.ipynb     Dual entitlement trees unified in Ranger
  governance-comparison.ipynb    Arrow paths with governance delta + latency

deploy/
  docker-compose.yml              Gravitino + Ranger + Trino stack (Glue Data Catalog, Ranger enforcement)
  user-data.sh                    EC2 bootstrap script (clones repo, runs canonical compose)
  provision.sh                    Full provisioning: catalogs, data, policies, enforcement gate
  init-ranger-db.sql.template     Ranger DB init (password substituted by make setup)
  trino-config/                   Trino config (direct catalogs + Ranger access control)
  download-ranger-plugin.sh       Ranger Trino plugin (SHA-512 verified)
  setup-trino-connector.sh        Gravitino Trino connector (SHA-256 verified)
  download-spark-connector.sh     Spark connector JARs
  generate-rules-json.sh          Fallback: export Ranger policies to Trino file-based rules

contracts/                        Generated agent pipeline status (gitignored)
```

## Test Tiers

Tests skip gracefully when infrastructure is not configured. A fresh clone with an empty `.env` runs local-only tests; the rest show as skipped, not failed.

| Tier | Tests | Required env vars |
|------|-------|-------------------|
| **Local only** | Unit tests + Arrow comparison (~40+) | None — `make setup` |
| **+ AWS** | Spectrum, S3/Arrow paths, Glue/IAM policies | `S3_BUCKET`, `REDSHIFT_HOST` |
| **+ Snowflake** | Snowflake query + policy tests | `SNOWFLAKE_ACCOUNT` |
| **+ Federation stack** | Trino, Ranger enforcement, Gravitino tests | `TRINO_HOST`, `RANGER_HOST`, `GRAVITINO_HOST` |
| **Full** | All tests including UC-11 enforcement | All variables in `.env.template` |

## Policy Extractors

Eight extractors normalize platform-native policies into Ranger's canonical schema:

| Extractor | Source | Method |
|-----------|--------|--------|
| `lf_to_ranger` | Lake Formation | `boto3 list_permissions()` |
| `glue_iam_to_ranger` | Glue resource policies + IAM | `GetResourcePolicies` + `SimulatePrincipalPolicy` |
| `redshift_to_ranger` | Redshift RBAC | `svv_relation_privileges` system views |
| `snowflake_to_ranger` | Snowflake RBAC + masking | `SHOW GRANTS`, `SHOW MASKING POLICIES` |
| `uc_to_ranger` | Unity Catalog | `databricks-sdk` grants API |
| `immuta_to_ranger` | Immuta ABAC | REST API `/policy`, `/permissions` |
| `iceberg_gap_fill` | Iceberg cold tier | Gap-fill policies for S3 Iceberg tables |
| `bedrock_to_ranger` | Bedrock models | Mirror model access policies |

Extractors run in priority order (Immuta first, Bedrock last). Each is idempotent — running twice produces the same Ranger state. Provenance labels track source system, extraction timestamp, and original grant text.

### Drift Detection

Each extraction run compares current policies against a saved snapshot:
- **Added/removed/modified** policies are logged
- **Security alerts** fire when masking or deny policies are removed
- Snapshots are saved only on successful extraction (not on abort)
- If >50% of pushes fail, extraction aborts to prevent inconsistent state

### Entitlement Matrix

A unified flat view of all Ranger policies for audit and comparison:

```bash
python -m src.reports.entitlement_matrix
```

## Demo Notebooks

```bash
pip install -e '.[demo]'
jupyter lab --no-browser --port=8888
```

## Key Design Decisions

1. **Ranger mirrors, platforms enforce.** Ranger is the canonical policy store for visibility and audit. Source platforms remain the enforcement backstop.
2. **Lossy translation is documented, not hidden.** Immuta's purpose-based ABAC cannot be fully represented in Ranger's RBAC model. The semantic loss is labeled and tracked.
3. **Arrow governs at the boundary.** Arrow Flight SQL delivers governed results efficiently. Direct S3 Arrow reads bypass Trino governance — this is a documented tradeoff.
4. **Deterministic test data.** All generated data uses `seed=42` for reproducibility.
5. **Ranger enforces at Trino.** Trino 479's built-in Ranger access-control plugin provides policy enforcement on federated queries. A file-based fallback (`generate-rules-json.sh`) can export Ranger policies to Trino's rules.json format if needed.

## License

[Apache License 2.0](LICENSE)
