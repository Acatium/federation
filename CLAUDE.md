# Federated Data Governance Reference Implementation

## What This Is

Reference implementation proving federated metadata, policy, and query execution
across real AWS (Glue/Redshift/Spectrum/Lake Formation), Databricks (Unity Catalog),
and Snowflake using Apache Gravitino, Trino, and Apache Ranger.

## The Problem

Organizations independently adopt AWS, Databricks, and Snowflake. Each platform
has its own access controls, but there is no unified catalog, no cross-platform
query engine, no unified policy view, and no unified audit trail. The federation
layer sits ABOVE existing platforms — it does NOT replace anything.

## Two-Tier Governance Model

Every dataset has governance. There is no "ungoverned" tier.

- **Tier 1 — Platform-native:** Redshift RBAC, Snowflake RBAC, UC ACLs, Lake Formation, IAM.
- **Tier 2 — FGAC (Immuta):** Column masking, row filtering, purpose-based access. Selected sensitive datasets only.

Every dataset tagged in Gravitino: `governance_tier: "platform_native" | "immuta_fgac"`

## Ranger's Dual Role

1. **Canonical policy mirror** (all datasets, both tiers): extracts and normalizes policies into a single store. Unified audit console.
2. **Enforcement at Trino federation layer**: For Tier 1, Ranger enforces mirrored platform grants. For Tier 2, the FGAC layer handles fine-grained controls, Ranger provides a coarse-grained floor.

## Architecture Safety Property ("Safe by Default")

- Over-permissive Ranger (stale allow): Platform-native enforcement is the backstop,
  per user only with identity passthrough; through a shared service account it leaks
- Under-permissive Ranger (stale deny): User blocked until sync — fail-closed
- Identity mode is part of the safety model (`IdentityMode` in `src/governance/safety_model.py`)

## Build & Test

```bash
source .venv/bin/activate
pytest tests/unit                        # Offline unit suite (82) — no infra, runs in CI
pytest tests/validation/ -v --tb=short   # Validation suite (88) — REQUIRES the 6-container stack + cloud creds
python -m src.validators.contract_validator  # Check contracts
```

### Validation Suite Structure (88 tests)

| Scenario | File | Tests | What It Proves |
|----------|------|-------|---------------|
| S1: The Report | `test_scenario1_the_report.py` | 21 | Discover → Build → Insight across 5 platforms |
| S2: The Audit | `test_scenario2_the_audit.py` | 23 | Numeric fidelity, audit trail, unified entitlements |
| S3: Failure Modes | `test_scenario3_the_failure_modes.py` | 27 | Safe-by-default, governance contrast, FGAC, evolution |
| S4: The Identities | `test_scenario4_the_identities.py` | 6 | Same SQL, different views per persona |
| Conclusion | `test_conclusion.py` | 11 | Three planes, three access patterns, honest gaps |

Other test tiers (`tests/unit/`, `tests/positive/`, `tests/regulatory/`, `tests/performance/`)
exist alongside the validation suite; only the validation suite is captured into results.
(`tests/negative/` and `tests/arrow/` do not exist — earlier docs referenced them in error.)

## Demo Notebooks

```bash
pip install -e '.[demo]'
jupyter lab --no-browser --port=8888
```

Three notebooks:
- **safe-by-default.ipynb** — Live revoke-at-source demo proving the safety property.
- **spectrum-proof-point.ipynb** — Dual entitlement trees (Redshift RBAC + Lake Formation) unified in Ranger.
- **governance-comparison.ipynb** — Arrow query paths with governance delta and latency chart.

## Code Standards

- Python 3.11+, type hints on all functions, docstrings on all public functions
- No hardcoded credentials — environment variables via `.env`
- Deterministic data generation (seed=42)
- `logging` module only — no `print()`
- Specific exception handling — no bare `except`
- Simulated components marked with `# SIMULATION NOTE:` comments

## File Conventions

- Python: `snake_case.py` | Config: `kebab-case.yml` | Tests: `test_<scenario>.py`
