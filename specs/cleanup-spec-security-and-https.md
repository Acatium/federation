# Cleanup Spec: Security Audit Remediation + Trino HTTPS Migration

## Context

An adversarial audit (2026-03-01) identified 4 must-fix and 6 should-fix items across security,
code quality, and operational readiness. This spec addresses all 10, with item 6 upgraded to
full Trino HTTPS using a self-signed certificate.

**Audit verdict:** Application code is solid; deploy tooling and transport security need work.

---

## Step 1: Delete `deploy/fix_ranger_policies.py`

**Problem:** Hardcoded `AUTH = "admin:rangerR0cks!"` on line 13, committed to git. The script
duplicates functionality already in `src/extractors/base.py` (`push_policy()`, `_ensure_ranger_principals()`).

**Action:** Delete the file. It's a one-off debugging script that shouldn't exist.

**File:** `deploy/fix_ranger_policies.py` (delete)

---

## Step 2: Generate dependency lock file

**Problem:** All deps use `>=` lower bounds with no upper bounds or lock file. Non-deterministic builds.

**Action:** Run `pip-compile` (from `pip-tools`) to generate `requirements-lock.txt` from
`pyproject.toml`. Add a note in README referencing it.

**Files:**
- `requirements-lock.txt` (new — generated)
- `Makefile` — add `lock` target: `pip-compile -o requirements-lock.txt pyproject.toml`

---

## Step 3: Move audit spool out of `/tmp`

**Problem:** `ranger-trino-audit.xml:19` spools audit events to `/tmp/trino-ranger-audit-spool`.
World-writable, lost on container restart.

**Action:** Change to `/var/lib/trino/ranger-audit-spool`. Add a named volume in docker-compose
to persist it.

**Files:**
- `deploy/trino-config/ranger-trino-audit.xml` line 19: `/tmp/trino-ranger-audit-spool` → `/var/lib/trino/ranger-audit-spool`
- `deploy/docker-compose.yml` trino volumes: add `trino-audit-spool:/var/lib/trino/ranger-audit-spool`
- `deploy/docker-compose.yml` bottom volumes section: add `trino-audit-spool:`

---

## Step 4: Replace `print()` with `logger` in source

**Problem:** 4 `print()` calls violate the project's "logging module only" standard.

**Action:** Replace each with appropriate `logger.info()` call.

**Files and lines:**
- `src/reports/entitlement_matrix.py:279` — `print(df)` → `logger.info("Entitlement matrix:\n%s", df)`
- `src/reports/entitlement_matrix.py:281` — `print("No policies...")` → `logger.info("No policies...")`
- `src/reports/final_report.py:2199` — `print(f"Report generated: {result}")` → `logger.info("Report generated: %s", result)`
- `src/reports/stakeholder_briefing.py:787` — `print(f"Briefing written to {path}")` → `logger.info("Briefing written to %s", path)`

---

## Step 5: Add "What You Need" section to README

**Problem:** Prerequisites are scattered. No clear local-vs-cloud distinction.

**Action:** Add a "Prerequisites" section after the intro and a "Local vs Cloud" subsection
in Quick Start. Content:

```markdown
## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | 3.12 recommended |
| Docker + Compose | v2+ | `docker compose version` to verify |
| Java | 17+ | For Spark tests only |

### What runs locally (no accounts needed)
- Gravitino, Ranger, Trino, MySQL, PostgreSQL, Solr (all via Docker)
- Unit tests, Arrow comparison tests

### What needs cloud accounts
| Service | What it's used for | Env vars |
|---------|-------------------|----------|
| AWS (Glue, Redshift, S3, Lake Formation) | Platform-native governance | `AWS_*`, `REDSHIFT_*`, `GLUE_*` |
| Snowflake | Cross-platform query federation | `SNOWFLAKE_*` |
| Databricks (Unity Catalog) | Credential vending, UniForm | `DATABRICKS_*` |

Tests skip gracefully when cloud services aren't configured.
```

**File:** `README.md`

---

## Step 6: Trino HTTPS with self-signed certificate

**Problem:** All Trino communication is plaintext HTTP on port 8080.

**Action:** Generate a self-signed JKS keystore, configure Trino for HTTPS on 8443,
expose as 443 externally. Add `TRINO_SCHEME` env var following existing `RANGER_SCHEME` pattern.

### 6a. Create certificate generation script

**File:** `deploy/generate-trino-cert.sh` (new)

```bash
#!/usr/bin/env bash
# Generate self-signed JKS keystore for Trino HTTPS
CERT_DIR="$(dirname "$0")/trino-certs"
mkdir -p "$CERT_DIR"
keytool -genkeypair \
  -alias trino \
  -keyalg RSA -keysize 2048 \
  -validity 365 \
  -keystore "$CERT_DIR/trino.jks" \
  -storepass changeit -keypass changeit \
  -dname "CN=trino,O=Federation,C=US" \
  -ext "SAN=dns:trino,dns:localhost,ip:127.0.0.1"
echo "Keystore: $CERT_DIR/trino.jks"
```

### 6b. Trino config.properties

**File:** `deploy/trino-config/config.properties`

Change lines 5-6:
```properties
# Before
http-server.http.port=8080
discovery.uri=http://localhost:8080

# After
http-server.http.enabled=false
http-server.https.enabled=true
http-server.https.port=8443
http-server.https.keystore.path=/etc/trino/trino.jks
http-server.https.keystore.key=changeit
discovery.uri=https://localhost:8443
```

### 6c. docker-compose.yml — Trino service

**File:** `deploy/docker-compose.yml`

- Line 138: `"8080:8080"` → `"443:8443"`
- Line 184: healthcheck → `curl -fk https://localhost:8443/v1/info` (`-k` for self-signed)
- Trino volumes: add `./trino-certs/trino.jks:/etc/trino/trino.jks:ro`
- Test-runner env: `TRINO_PORT: "8443"`, add `TRINO_SCHEME: "https"`

### 6d. .env.template

**File:** `.env.template`

Add after TRINO_PORT:
```bash
TRINO_SCHEME=https
TRINO_VERIFY_CERT=false   # Set to 'true' with CA-signed cert in production
```

Update TRINO_PORT default comment to 8443.

### 6e. src/utils/config.py

**File:** `src/utils/config.py` — add after line 34:
```python
TRINO_SCHEME: str = os.getenv("TRINO_SCHEME", "http")
TRINO_VERIFY_CERT: bool = os.getenv("TRINO_VERIFY_CERT", "true").lower() == "true"
```

### 6f. tests/conftest.py — 6 trino.dbapi.connect() calls

Add a shared helper at the top of the Trino fixtures section:
```python
def _trino_connect_kwargs() -> dict[str, Any]:
    """Common Trino connection parameters including HTTPS support."""
    scheme = os.getenv("TRINO_SCHEME", "http")
    verify = os.getenv("TRINO_VERIFY_CERT", "true").lower() == "true"
    kwargs: dict[str, Any] = {"http_scheme": scheme}
    if scheme == "https" and not verify:
        kwargs["verify"] = False
    return kwargs
```

Then update all 6 fixtures (lines 166, 186, 835, 849, 863, 877) to unpack `**_trino_connect_kwargs()`.

### 6g. src/arrow/comparison.py + benchmarks.py

Same pattern — add `http_scheme` from env var to `trino.dbapi.connect()` calls.

**Files:**
- `src/arrow/comparison.py:69-75`
- `src/arrow/benchmarks.py` (equivalent location)

### 6h. Notebooks (3 files)

Update Trino connection cells to include `http_scheme=os.getenv('TRINO_SCHEME', 'http')`.

**Files:**
- `notebooks/stale-allow-leak.ipynb (formerly safe-by-default.ipynb)`
- `notebooks/spectrum-proof-point.ipynb`
- `notebooks/governance-comparison.ipynb`

### 6i. deploy/provision.sh

Update Trino URL references to use `${TRINO_SCHEME:-https}` and add `-k` to curl calls
that hit Trino.

**What doesn't change:** Ranger plugin config (embedded in Trino JVM), all catalog properties
(downstream connections), Ranger/Solr/Gravitino configs (container-internal, stay on HTTP).

---

## Step 7: Add container resource limits

**Problem:** No memory/CPU limits. Runaway Trino query can starve Ranger.

**Action:** Add `deploy.resources.limits` to docker-compose.yml for the three heavy services.
Based on the r6i.xlarge spec (4 vCPU, 32 GB) in the compose comment on line 2.

```yaml
trino:
  deploy:
    resources:
      limits:
        memory: 22G    # JVM heap is 20G per jvm.config
ranger:
  deploy:
    resources:
      limits:
        memory: 4G
gravitino:
  deploy:
    resources:
      limits:
        memory: 2G
```

MySQL, Postgres, Solr share remaining ~4G (small footprint, no explicit limits needed).

**File:** `deploy/docker-compose.yml`

---

## Step 8: Deeper Ranger health check

**Problem:** Current check (`curl -f http://localhost:6080/login.jsp`) passes even when the
Trino service isn't registered.

**Action:** Change to check the Ranger service REST API:
```yaml
healthcheck:
  test: ["CMD-SHELL", "curl -sf -u admin:${RANGER_ADMIN_PASSWORD} http://localhost:6080/service/public/v2/api/service/dev_trino | grep -q dev_trino"]
```

This verifies Ranger is up AND the Trino service definition exists.

**File:** `deploy/docker-compose.yml` lines 123-128

**Note:** The dev_trino service is created by `provision.sh`, not at container startup. The
health check should use the login.jsp check during initial startup (start_period: 180s) and
only enforce the deeper check after provisioning. Consider a two-phase approach: keep login.jsp
for Docker health, add the service check to `make health-check` instead.

---

## Step 9: Add `make health-check` target

**Problem:** No single command to verify all services after deploy.

**Action:** Add to Makefile:
```makefile
health-check:
	@docker compose --env-file .env -f deploy/docker-compose.yml ps --format "table {{.Service}}\t{{.Status}}"
```

**File:** `Makefile` — add target + add to `.PHONY` list

---

## Step 10: Add rollback tracking to push_all()

**Problem:** If extraction aborts at >50% failure, already-pushed policies remain in Ranger
(partial governance state).

**Action:** Track pushed policy IDs during `push_all()`. On abort, log them as a warning with
a clear message so operators can decide whether to revert. Do NOT auto-delete — that's more
dangerous than partial state. Instead, provide the information.

**File:** `src/extractors/base.py`

In `push_all()` (line 272):
- Add `pushed_ids: list[int] = []` before the loop
- After successful `push_policy()`, append the policy ID (available from the Ranger response)
- On abort, log: `"Partially pushed policies (IDs: %s) — review manually or re-run to complete"`
- Store `self._last_pushed_ids = pushed_ids` for caller introspection

This requires `push_policy()` to return the policy ID on success (currently returns `bool`).
Change return type to `int | None` (ID on success, None on failure). Update `push_all()` accordingly.

---

## Makefile updates (consolidated)

Add to Makefile:
```makefile
generate-cert:
	bash deploy/generate-trino-cert.sh

lock:
	pip-compile -o requirements-lock.txt pyproject.toml

health-check:
	@docker compose --env-file .env -f deploy/docker-compose.yml ps --format "table {{.Service}}\t{{.Status}}"
```

Update `setup` target to include `generate-cert`.
Update `.PHONY` to include new targets.

---

## File change summary

| File | Action |
|------|--------|
| `deploy/fix_ranger_policies.py` | DELETE |
| `deploy/generate-trino-cert.sh` | NEW |
| `deploy/trino-certs/trino.jks` | NEW (generated, .gitignore) |
| `requirements-lock.txt` | NEW (generated) |
| `deploy/trino-config/ranger-trino-audit.xml` | EDIT (spool path) |
| `deploy/trino-config/config.properties` | EDIT (HTTPS config) |
| `deploy/docker-compose.yml` | EDIT (ports, health, volumes, limits, test-runner) |
| `.env.template` | EDIT (add TRINO_SCHEME, TRINO_VERIFY_CERT) |
| `src/utils/config.py` | EDIT (add TRINO_SCHEME, TRINO_VERIFY_CERT) |
| `src/reports/entitlement_matrix.py` | EDIT (print → logger) |
| `src/reports/final_report.py` | EDIT (print → logger) |
| `src/reports/stakeholder_briefing.py` | EDIT (print → logger) |
| `src/extractors/base.py` | EDIT (rollback tracking in push_all) |
| `tests/conftest.py` | EDIT (HTTPS support in 6 fixtures) |
| `src/arrow/comparison.py` | EDIT (HTTPS support) |
| `src/arrow/benchmarks.py` | EDIT (HTTPS support) |
| `notebooks/stale-allow-leak.ipynb (formerly safe-by-default.ipynb)` | EDIT (HTTPS support) |
| `notebooks/spectrum-proof-point.ipynb` | EDIT (HTTPS support) |
| `notebooks/governance-comparison.ipynb` | EDIT (HTTPS support) |
| `deploy/provision.sh` | EDIT (HTTPS URLs) |
| `README.md` | EDIT (prerequisites section) |
| `Makefile` | EDIT (new targets) |

---

## Verification

1. `make generate-cert` — produces `deploy/trino-certs/trino.jks`
2. `make deploy` — all 6 containers start, health checks pass
3. `make health-check` — shows all services healthy
4. `curl -k https://<TRINO_HOST>:443/v1/info` — Trino responds over HTTPS
5. `pytest tests/validation/ -v --tb=short` — all existing tests pass (88 tests)
6. `pip-compile` produces `requirements-lock.txt`
7. Verify `deploy/fix_ranger_policies.py` no longer exists
8. Verify no `print()` in `src/` via `grep -rn 'print(' src/`

---

## Estimated effort

| Step | Time |
|------|------|
| Steps 1, 3, 4 (delete, spool, print) | 10 min |
| Step 2 (lock file) | 5 min |
| Step 5 (README) | 15 min |
| Step 6 (HTTPS — all substeps) | 60 min |
| Steps 7, 8, 9 (limits, health, make target) | 15 min |
| Step 10 (rollback tracking) | 20 min |
| Testing & fixing | 30 min |
| **Total** | **~2.5 hours** |
