# Federated Data Governance Across Databricks, Snowflake and AWS

Regulated organizations rarely run one data platform. AWS, Databricks and Snowflake each
enforce access their own way, so "who can see this customer's data, everywhere?" takes
three teams to answer. The usual proposal is a governance layer above the platforms: mirror
every platform's grants into one canonical policy store, query across them through one
engine, and audit in one place, while the platforms keep enforcing.

This repository tests whether that design is safe. It mirrors live grants from Unity
Catalog, Snowflake, Redshift, Lake Formation and Glue/IAM into
[Apache Ranger](https://ranger.apache.org/), queries across the platforms with
[Trino](https://trino.io/), and federates their metadata with
[Apache Gravitino](https://gravitino.apache.org/).

## The question

A mirror is always slightly out of date. When a platform revokes a grant, Ranger keeps
allowing it until the next sync. The design's claim is that this is harmless because the
platform still enforces underneath: a stale allow in the mirror meets a deny at the source.

## The finding

The claim holds only if the platform checks the end user. Federation engines usually
connect to each platform with one service credential, and this deployment does too
(`deploy/trino-config/`). The platform then checks what the service account can reach, not
what the user may see, so a revoked user keeps access until the mirror catches up.

| Mirror (Ranger) | Platform, for this user | Identity passthrough | Shared service account      |
| --------------- | ----------------------- | -------------------- | --------------------------- |
| Stale allow     | Revoked                 | Blocked at source    | **Data exposed until sync** |
| Stale deny      | Granted                 | Blocked until sync   | Blocked until sync          |
| Allow           | Granted                 | Allowed              | Allowed                     |

`src/governance/safety_model.py` computes these outcomes per request, from the Ranger
policies the extractors produce and the platforms' current grants.
`tests/unit/test_identity_mode.py` exercises both columns.

### A second failure: several authorities over one resource

A mirror also has to combine platforms that govern the same data. On AWS, reading a
Lake Formation-governed table needs IAM and Lake Formation to allow it, and an Immuta
policy sits on top of a platform's own grants: access is the intersection. Ranger holds one
access policy per resource, so when each source pushes separately the second push
overwrites the first. The last writer wins, and the result flips with the run order:
contractors that only IAM allows get in when Glue/IAM runs last, and analysts that only
Lake Formation allows get in when it runs last
(`tests/unit/test_authority_conflicts.py`).

`FederatedSync` (`src/sync/federated.py`) extracts every source together, combines
access policies that share a resource into the intersection of what each source allows
(keeping every deny), and pushes one policy set. If any source fails to extract, nothing
is pushed.

## Comparing the alternatives

A mirror is one of four ways to govern access across platforms. The others author policy
centrally and push it into each platform's native controls, make one catalog the authority
(Iceberg REST with credential vending), or enforce in the query engine through a policy
engine such as OPA or Ranger's plugin.

`src/governance/patterns.py` compares them on one event: a person's access is revoked at
the pattern's own source of truth (the platform for a mirror, the central store for
push-down, the catalog for a catalog authority, the engine's policy store for engine
enforcement). How long can they still read the data? It is a model: its conclusions follow
from the enforcement rules it encodes. The evidence that the mirror rows match a real
deployment is the live test below; the other rows are reasoning, not measurement. The timings are example
assumptions (15-minute batch sync, 30-second event feed, 60-second push and decision cache,
one-hour vended credentials); change them in `Timings` and regenerate the table with
`python -m src.governance.patterns`. The Databricks path in this repository is itself a
catalog authority (Unity Catalog vends the storage credentials), so mirroring over it is
bounded by those credentials as well as by the sync. If people revoke at the platform
rather than in the engine's store, engine enforcement inherits the mirror's sync window.

| Pattern | Passthrough | Per-group accounts | Shared account |
|---|---|---|---|
| Mirror, batch sync | 0 | ≤ 15 min (avg 7.5 min) | ≤ 15 min (avg 7.5 min) |
| Mirror, event-driven sync | 0 | 30 s | 30 s |
| Mirror, batch sync, over vended credentials | ≤ 15 min (avg 7.5 min) | ≤ 15 min (avg 7.5 min) | ≤ 15 min (avg 7.5 min) |
| Push down to native controls | 60 s | **never** | **never** |
| Catalog as authority | ≤ 60 min (avg 30 min) | **never** | **never** |
| Enforce in the engine | ≤ 60 s (avg 30 s) | ≤ 60 s (avg 30 s) | ≤ 60 s (avg 30 s) |

The identity the connector presents decides the result more than the pattern does.
Push-down and catalog policies are written for people; when the query arrives as a shared
account, they never match the revoked person. Enforcing in the engine, where the person is
still visible, bounds exposure whatever credential the engine uses downstream, and a mirror
feeding the engine inherits that bound plus its sync window.

`notebooks/stale-allow-leak.ipynb` and
`test_stale_allow_leaks_through_the_shared_connector` run the mirror row against live
Redshift: revoke the user at the source, query through Trino and get rows back, sync, and
get refused.

Estates differ in which patterns they can use at all:

| Pattern | Open formats | Cloud warehouses | On-prem databases | Mainframe | Blind spot |
|---|---|---|---|---|---|
| Mirror platform grants into one policy store | Yes | Yes (Snowflake, Redshift extractors here) | Yes, from grant views (Oracle `DBA_TAB_PRIVS`, DB2 `SYSCAT.TABAUTH`, SQL Server `sys.database_permissions`) | DB2 for z/OS catalog grants; RACF profiles for IMS and VSAM | Visibility, not enforcement: safe per person only with passthrough |
| Author centrally, push down to native controls | Yes (Unity Catalog ABAC, Polaris RBAC) | Yes (row access and masking policies; Redshift RLS and masking) | Where native row and column controls exist (Oracle VPD, DB2 RCAC, SQL Server RLS) | DB2 for z/OS RCAC; IMS and VSAM only at RACF dataset level | Anything native controls cannot express; shared-account paths |
| One catalog is the authority | Yes: the pattern's home | Through Iceberg tables, or as foreign catalogs behind one connection credential | As foreign catalogs behind one connection credential | No | Everything not registered in the catalog |
| Enforce in the query engine | Yes | Yes, for queries through the engine | Yes, for queries through the engine | Where a connector exists | Applications that connect to the source directly |

## What it means for a platform team

1. **Enforce where the person is still visible.** With identity passthrough to every
   platform, push-down or a catalog authority closes a revocation quickly. With shared
   connector accounts, which most brownfield estates depend on, only the engine (or a
   mirror feeding it) can cut off one person.
2. **Treat the sync window as a security control.** Feed the mirror from each platform's
   grant-change records (CloudTrail for Lake Formation, Unity Catalog's audit system table,
   Snowflake's account-usage views) rather than a schedule, and give connectors one account
   per group or sensitivity tier so the platform's ceiling is the group's access, not
   everyone's.
3. **Choose by estate.** Open-format estates suit a catalog authority. Brownfield estates
   need push-down where native row and column controls exist, a mirror for visibility
   everywhere else, and the engine as the enforcement point for cross-platform queries.
4. **Govern the paths around the engine.** Direct application connections and reads from
   object storage with static credentials bypass every control above. Vended, scoped
   credentials keep the platform's enforcement in the path (`ARROW_TRANSPORTS` in the
   safety model).
5. **Never let the mirror grant more than the source, and delete what it stops granting.**
   Privileges with no data-access meaning, such as `BROWSE` and `MANAGE`, map to nothing;
   an extraction that cannot read every grant is refused rather than pushed half-complete
   (`src/extractors/uc_to_ranger.py`); and each sync deletes this source's allow policies
   the platform no longer grants, while reporting removed masking and deny policies for
   review rather than deleting them (`BaseExtractor.reconcile_removed`).
6. **Combine authorities by AND, in one pass.** Where two platforms govern the same data,
   the mirror must allow only what both allow. Syncing sources one at a time into a
   store that holds one policy per resource makes the last writer win.
7. **Label what translation loses.** Immuta's purpose-based rules do not fit Ranger's role
   model; each policy carries labels for what was lost rather than dropping it silently.

## How it is built

```
DELIVERY    Arrow Flight SQL          governed columnar transport
QUERY       Trino + Ranger            federated SQL + policy enforcement
GOVERNANCE  Ranger                    canonical policy store + unified audit
CATALOG     Gravitino                 federated metadata across all platforms
```

Each extractor reads a platform's native grants and normalizes them into Ranger's schema,
with provenance labels (source system, extraction time, original grant text):

| Extractor             | Source                                                              | Status                     |
| --------------------- | ------------------------------------------------------------------- | -------------------------- |
| `uc_to_ranger`        | Unity Catalog permissions REST API                                  | Live                       |
| `snowflake_to_ranger` | Snowflake RBAC and masking (`SHOW GRANTS`, `SHOW MASKING POLICIES`) | Live                       |
| `redshift_to_ranger`  | Redshift RBAC (`svv_relation_privileges`)                           | Live                       |
| `lf_to_ranger`        | Lake Formation (`list_permissions`)                                 | Live                       |
| `glue_iam_to_ranger`  | Glue resource policies and IAM (`SimulatePrincipalPolicy`)          | Live                       |
| `immuta_to_ranger`    | Immuta ABAC (REST)                                                  | Live pipeline, mock source |
| `iceberg_gap_fill`    | S3 Iceberg cold tier                                                | Simulated                  |
| `bedrock_to_ranger`   | Bedrock models                                                      | Simulated                  |

Extractors run in priority order and are idempotent. Each run is compared with the last
snapshot to report drift, and a push aborts if most writes fail. An entitlement matrix
(`src/reports/entitlement_matrix.py`) gives one cross-platform view of every policy for
audit. Regulatory scenarios for BCBS 239, DORA, GDPR and SOX run against the live stack.

## Running it

The unit suite runs offline and in CI:

```bash
pip install pytest pytest-timeout requests boto3 python-dotenv polars jinja2 \
            faker psycopg2-binary snowflake-connector-python databricks-sdk
pytest tests/unit
```

Everything else needs the six-container stack (Gravitino, Ranger, Trino, MySQL, Postgres,
Solr) and live AWS, Snowflake and Databricks accounts:

```bash
cp .env.template .env && make setup && make deploy && make provision
make test
```

| Suite                | Covers                                                           | Needs      |
| -------------------- | ---------------------------------------------------------------- | ---------- |
| `tests/unit/`        | Safety model, extractors, drift, sync config, entitlement matrix | Nothing    |
| `tests/positive/`    | Catalog, query, Spectrum and enforcement use cases               | Live stack |
| `tests/regulatory/`  | BCBS 239, DORA, GDPR, SOX scenarios                              | Live stack |
| `tests/validation/`  | End-to-end scenario suite                                        | Live stack |
| `tests/performance/` | Benchmarks                                                       | Live stack |

Without the stack, the live suites fail at fixture setup rather than skip.

## Limits

- **Identity.** Connectors use shared service credentials, and users are local Trino users
  rather than an enterprise identity provider (`TestHonestGaps` in
  `tests/validation/test_conclusion.py`). The finding above is the consequence.
- **Immuta** reads from a mock API (`src/mocks/immuta_mock.py`); live Immuta enforcement is
  not wired up.
- **Bedrock and Iceberg** extractors generate deterministic policies from a known schema
  rather than reading a live source; each is marked `SIMULATION NOTE` in the code.
- **Regulatory results** are produced by `make test` against the live stack and are not
  committed.

## Layout

```
src/
  extractors/   Platform grants → Ranger policies
  governance/   Safety model, request simulator, pattern comparison
  reports/      Entitlement matrix, report generator
  sync/         Federated sync (AND across sources), sync intervals, drift detection
  arrow/        Arrow Flight SQL / ADBC connectors and benchmarks
  loaders/      Deterministic test data (seed=42)
  models/       Bedrock model catalog (simulated offline)
  mocks/        Mock Immuta API
tests/          unit · positive · regulatory · validation · performance
deploy/         docker-compose stack and provisioning
notebooks/      Live walkthroughs: the stale-allow leak, Spectrum, query paths
```

## License

[Apache License 2.0](LICENSE)
