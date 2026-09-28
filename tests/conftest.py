"""Shared test fixtures for all test categories.

Includes a results-capture plugin that writes per-test evidence
(log output, pass/fail, duration) to data/test_results.json for
the final report.
"""

import json
import os
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Results capture plugin — saves per-test evidence to JSON
# ---------------------------------------------------------------------------

_RESULTS_PATH = Path(__file__).resolve().parent.parent / "data" / "test_results.json"
_VALIDATION_DIR = Path(__file__).resolve().parent / "validation"

# Session-level storage: node_id → result dict
_test_results: dict[str, dict[str, Any]] = {}


def _is_validation_test(item: pytest.Item) -> bool:
    """Return True if the test lives under tests/validation/."""
    return _VALIDATION_DIR in Path(item.fspath).resolve().parents


class _PerTestLogHandler(logging.Handler):
    """Captures log records into a list for the duration of a single test."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(self.format(record))
        except Exception:
            pass


# Stash key for the per-test handler
_handler_key = pytest.StashKey[_PerTestLogHandler]()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Any:
    """Install a log handler for the duration of the test call phase."""
    handler = _PerTestLogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    item.stash[_handler_key] = handler
    start = time.monotonic()
    yield
    elapsed = time.monotonic() - start
    root.removeHandler(handler)

    # Only capture results for validation tests
    if not _is_validation_test(item):
        return

    # Build a module-relative key: "test_uc1_catalog_discovery::test_metalake_exists"
    module = Path(item.fspath).stem if item.fspath else item.module.__name__
    node_key = f"{module}::{item.name}"

    _test_results[node_key] = {
        "module": module,
        "function": item.name,
        "logs": handler.records,
        "duration_s": round(elapsed, 3),
        # status filled in by pytest_runtest_makereport below
        "status": "unknown",
    }


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: Any) -> Any:
    """Record the pass/fail/skip outcome for the call phase."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call":
        module = Path(item.fspath).stem if item.fspath else item.module.__name__
        node_key = f"{module}::{item.name}"
        if node_key in _test_results:
            _test_results[node_key]["status"] = report.outcome  # passed/failed/skipped
    elif report.when == "setup" and report.skipped and _is_validation_test(item):
        module = Path(item.fspath).stem if item.fspath else item.module.__name__
        node_key = f"{module}::{item.name}"
        _test_results[node_key] = {
            "module": module,
            "function": item.name,
            "logs": [],
            "duration_s": 0,
            "status": "skipped",
        }


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    """Write captured results to JSON at the end of the test session."""
    if not _test_results:
        return
    _RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)

    results = dict(_test_results)

    output = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "total": len(results),
        "passed": sum(1 for r in results.values() if r["status"] == "passed"),
        "failed": sum(1 for r in results.values() if r["status"] == "failed"),
        "skipped": sum(1 for r in results.values() if r["status"] == "skipped"),
        "results": results,
    }
    _RESULTS_PATH.write_text(
        json.dumps(output, indent=2, default=str), encoding="utf-8"
    )
    logger.info("Test results written to %s (%d tests)", _RESULTS_PATH, len(results))


# ---------------------------------------------------------------------------
# Slow marker auto-registration
# ---------------------------------------------------------------------------


def pytest_configure(config: Any) -> None:
    """Register custom markers to avoid warnings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "spark: marks tests requiring PySpark")
    config.addinivalue_line("markers", "iceberg: marks tests requiring Iceberg")
    config.addinivalue_line("markers", "model_catalog: marks tests for Gravitino model catalog")
    config.addinivalue_line("markers", "cross_format: marks cross-format federation tests")
    config.addinivalue_line("markers", "enforcement: marks Ranger enforcement verification tests")
    config.addinivalue_line("markers", "unit: marks unit tests that run without infrastructure")


# ---------------------------------------------------------------------------
# Platform connections (session-scoped — reused across all tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def trino_conn() -> Iterator[Any]:
    """Governed Trino connection (session-scoped)."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    if not host:
        pytest.fail("TRINO_HOST not configured")
    port = int(os.getenv("TRINO_PORT", "8080"))
    logger.info("Connecting to Trino at %s:%s", host, port)
    conn = trino.dbapi.connect(
        host=host,
        port=port,
        user=os.getenv("TRINO_USER", "test_user"),
        catalog=os.getenv("TRINO_HIVE_CATALOG", "hive"),
    )
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def restricted_trino_conn() -> Iterator[Any]:
    """Trino connection as restricted_user (no Ranger policies — should be denied)."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    if not host:
        pytest.fail("TRINO_HOST not configured")
    port = int(os.getenv("TRINO_PORT", "8080"))
    logger.info("Connecting to Trino as restricted_user at %s:%s", host, port)
    conn = trino.dbapi.connect(
        host=host,
        port=port,
        user="restricted_user",
        catalog=os.getenv("TRINO_HIVE_CATALOG", "hive"),
    )
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def redshift_conn() -> Iterator[Any]:
    """Direct Redshift connection (session-scoped)."""
    import psycopg2

    host = os.getenv("REDSHIFT_HOST", "")
    if not host:
        pytest.fail("REDSHIFT_HOST not configured")
    logger.info("Connecting to Redshift at %s", host)
    conn = psycopg2.connect(
        host=host,
        port=int(os.getenv("REDSHIFT_PORT", "5439")),
        database=os.getenv("REDSHIFT_DATABASE"),
        user=os.getenv("REDSHIFT_USER"),
        password=os.getenv("REDSHIFT_PASSWORD"),
        sslmode="require",
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
    )
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def snowflake_conn() -> Iterator[Any]:
    """Direct Snowflake connection (session-scoped)."""
    import snowflake.connector

    account = os.getenv("SNOWFLAKE_ACCOUNT", "")
    if not account:
        pytest.fail("SNOWFLAKE_ACCOUNT not configured")
    logger.info("Connecting to Snowflake account %s", account)
    conn = snowflake.connector.connect(
        account=account,
        user=os.getenv("SNOWFLAKE_USER"),
        password=os.getenv("SNOWFLAKE_PASSWORD"),
        warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
        database=os.getenv("SNOWFLAKE_DATABASE"),
        role=os.getenv("SNOWFLAKE_ROLE") or None,
    )
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Ranger REST API helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def ranger_base_url() -> str:
    """Return the Ranger REST API base URL."""
    host = os.getenv("RANGER_HOST", "localhost")
    port = os.getenv("RANGER_PORT", "6080")
    scheme = os.getenv("RANGER_SCHEME", "http")
    return f"{scheme}://{host}:{port}"


@pytest.fixture(scope="session")
def ranger_auth() -> tuple[str, str]:
    """Return (user, password) for Ranger admin."""
    return (
        os.getenv("RANGER_ADMIN_USER", "admin"),
        os.getenv("RANGER_ADMIN_PASSWORD", ""),
    )


@pytest.fixture(scope="session")
def ranger_policies(ranger_base_url: str, ranger_auth: tuple[str, str]) -> list[dict[str, Any]]:
    """Fetch all Ranger policies for the dev_trino service."""
    if not os.getenv("RANGER_HOST", ""):
        pytest.fail("RANGER_HOST not configured")
    url = f"{ranger_base_url}/service/public/v2/api/policy"
    params = {"serviceName": "dev_trino"}
    try:
        resp = requests.get(url, params=params, auth=ranger_auth, timeout=30)
        resp.raise_for_status()
        policies = resp.json()
        logger.info("Fetched %d Ranger policies for dev_trino", len(policies))
        return policies
    except requests.RequestException as exc:
        logger.warning("Could not fetch Ranger policies: %s", exc)
        pytest.fail(f"Ranger unreachable: {exc}")


# ---------------------------------------------------------------------------
# Gravitino REST API helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def gravitino_base_url() -> str:
    """Return the Gravitino REST API base URL."""
    host = os.getenv("GRAVITINO_HOST", "localhost")
    port = os.getenv("GRAVITINO_PORT", "8090")
    scheme = os.getenv("GRAVITINO_SCHEME", "http")
    return f"{scheme}://{host}:{port}"


@pytest.fixture(scope="session")
def gravitino_metalake(gravitino_base_url: str) -> dict[str, Any]:
    """Fetch the 'federation' metalake metadata from Gravitino."""
    if not os.getenv("GRAVITINO_HOST", ""):
        pytest.fail("GRAVITINO_HOST not configured")
    url = f"{gravitino_base_url}/api/metalakes/federation"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        logger.info("Gravitino metalake response: %s", data)
        return data
    except requests.RequestException as exc:
        logger.warning("Could not contact Gravitino: %s", exc)
        pytest.fail(f"Gravitino unreachable: {exc}")


@pytest.fixture(scope="session")
def gravitino_catalogs(gravitino_base_url: str) -> list[str]:
    """List catalog names registered in the 'federation' metalake."""
    if not os.getenv("GRAVITINO_HOST", ""):
        pytest.fail("GRAVITINO_HOST not configured")
    url = f"{gravitino_base_url}/api/metalakes/federation/catalogs"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Gravitino returns {"identifiers": [{"namespace": [...], "name": "..."}, ...]}
        identifiers = data.get("identifiers", [])
        names = [i["name"] for i in identifiers if "name" in i]
        logger.info("Gravitino catalogs in metalake 'federation': %s", names)
        return names
    except requests.RequestException as exc:
        logger.warning("Could not list Gravitino catalogs: %s", exc)
        pytest.fail(f"Gravitino catalogs unavailable: {exc}")


# ---------------------------------------------------------------------------
# Immuta mock fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def immuta_policies() -> list[dict[str, Any]]:
    """Return mock Immuta policies (imported directly, no server required)."""
    from src.mocks.immuta_mock import POLICIES

    return POLICIES


@pytest.fixture(scope="session")
def immuta_permissions() -> list[dict[str, Any]]:
    """Return mock Immuta permissions (imported directly, no server required)."""
    from src.mocks.immuta_mock import PERMISSIONS

    return PERMISSIONS


@pytest.fixture(scope="session")
def immuta_datasources() -> list[dict[str, Any]]:
    """Return mock Immuta data sources (imported directly, no server required)."""
    from src.mocks.immuta_mock import DATA_SOURCES

    return DATA_SOURCES


# ---------------------------------------------------------------------------
# S3 / environment helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def s3_bucket() -> str:
    """Return the S3 bucket name for Parquet/Spectrum data."""
    bucket = os.getenv("S3_BUCKET", "")
    if not bucket:
        pytest.fail("S3_BUCKET not configured")
    return bucket


@pytest.fixture(scope="session")
def aws_region() -> str:
    """Return the AWS region."""
    return os.getenv("AWS_REGION", "us-east-2")


# ---------------------------------------------------------------------------
# Spark fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def spark_session() -> Iterator[Any]:
    """PySpark session with Iceberg native GlueCatalog (session-scoped).

    Uses Iceberg's native SparkCatalog + GlueCatalog directly instead of the
    Gravitino Spark connector. This avoids Gravitino issue #6035 where
    catalog-backend-impl is not passed through when catalog-backend=custom.

    SIMULATION NOTE: The Gravitino Spark connector (GravitinoSparkPlugin) has
    bug #6035 — it does not forward the 'catalog-backend-impl' property to the
    underlying Iceberg catalog when catalog-backend=custom. This was fixed after
    Gravitino 1.1.0. The workaround is to configure Spark with Iceberg's native
    SparkCatalog + GlueCatalog directly, which reads the same Glue-registered
    tables as the Trino iceberg_s3 catalog.

    Returns None if PySpark or connector JARs are not available.
    Tests that use this fixture must handle the None case by verifying
    configuration instead of executing live queries.
    """
    try:
        from pyspark.sql import SparkSession
    except ImportError:
        logger.info("pyspark not installed — Spark tests will verify configuration")
        yield None
        return

    s3_bucket = os.getenv("S3_BUCKET", "")
    aws_region = os.getenv("AWS_REGION", "us-east-2")
    glue_catalog_id = os.getenv("GLUE_CATALOG_ID", os.getenv("AWS_ACCOUNT_ID", ""))

    if not s3_bucket:
        logger.info("S3_BUCKET not configured — Spark tests will verify configuration")
        yield None
        return

    # Find Iceberg JARs (gravitino-spark-connector excluded from download script
    # due to bug #6035 — it should not be in the jars directory)
    jars_dir = os.getenv("SPARK_JARS_DIR", "")
    if not jars_dir:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        jars_dir = os.path.join(project_root, "jars")

    jar_files: list[str] = []
    if os.path.isdir(jars_dir):
        jar_files = [
            os.path.join(jars_dir, f)
            for f in os.listdir(jars_dir)
            if f.endswith(".jar")
        ]

    if not jar_files:
        logger.info(
            "No Iceberg JARs found in %s — Spark tests will verify configuration",
            jars_dir,
        )
        yield None
        return

    jars_csv = ",".join(jar_files)
    logger.info("Iceberg Spark JARs: %s", jars_csv)

    builder = (
        SparkSession.builder.master("local[2]")
        .appName("federation-test")
        .config("spark.jars", jars_csv)
        # --- Iceberg catalog (cold tier) ---
        # Native SparkCatalog + GlueCatalog — bypasses Gravitino Spark connector (#6035)
        .config("spark.sql.catalog.iceberg_s3", "org.apache.iceberg.spark.SparkCatalog")
        .config("spark.sql.catalog.iceberg_s3.catalog-impl", "org.apache.iceberg.aws.glue.GlueCatalog")
        .config("spark.sql.catalog.iceberg_s3.warehouse", f"s3://{s3_bucket}/iceberg/")
        .config("spark.sql.catalog.iceberg_s3.io-impl", "org.apache.iceberg.aws.s3.S3FileIO")
        .config("spark.sql.catalog.iceberg_s3.glue.id", glue_catalog_id)
        .config("spark.sql.catalog.iceberg_s3.glue.region", aws_region)
        # --- Hive/Parquet warm tier ---
        # The AWS Glue Data Catalog Hive metastore client JAR
        # (AWSGlueDataCatalogHiveClientFactory) is not available on Maven
        # Central and cannot be built from source (broken deps, awslabs#60).
        # Parquet warm tier tests read directly from S3 via spark.read.parquet()
        # instead of going through a Hive metastore catalog lookup.
        .config("spark.hadoop.fs.s3a.aws.credentials.provider",
                "com.amazonaws.auth.DefaultAWSCredentialsProviderChain")
        .config("spark.hadoop.fs.s3a.endpoint", f"s3.{aws_region}.amazonaws.com")
        .config(
            "spark.sql.extensions",
            "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions",
        )
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "1g")
    )

    spark = builder.getOrCreate()

    logger.info(
        "Spark session created with Iceberg native GlueCatalog "
        "(workaround for Gravitino #6035)"
    )
    yield spark
    spark.stop()


# ---------------------------------------------------------------------------
# Bedrock model catalog fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def gravitino_model_catalog() -> dict[str, Any]:
    """Return BedrockModelCatalog instance info.

    Falls back to local model definitions if Gravitino is unreachable.
    """
    from src.models.bedrock_catalog import BedrockModelCatalog

    catalog = BedrockModelCatalog()
    return catalog.get_catalog_info()


@pytest.fixture(scope="session")
def bedrock_models() -> list[dict[str, Any]]:
    """Return the list of Bedrock model definitions."""
    from src.models.bedrock_catalog import BEDROCK_MODELS

    return BEDROCK_MODELS


# ---------------------------------------------------------------------------
# Iceberg fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def iceberg_catalog_name() -> str:
    """Return the Iceberg catalog name as registered in Gravitino."""
    return os.getenv("ICEBERG_CATALOG", "iceberg_s3")


# ---------------------------------------------------------------------------
# Spark guard fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def require_spark(spark_session: Any) -> Any:
    """Skip test if Spark session is unavailable (no JARs or no Gravitino)."""
    if spark_session is None:
        pytest.fail("Spark session unavailable (missing JARs or GRAVITINO_HOST)")
    return spark_session


# ---------------------------------------------------------------------------
# Extractor-based fixtures (session-scoped, run real extractors)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def immuta_extracted_policies() -> list[dict[str, Any]]:
    """Run ImmutaExtractor conversion logic on mock data.

    Feeds mock Immuta data directly into the extractor's conversion methods,
    bypassing the HTTP layer. This tests the real ABAC→RBAC translation
    logic without needing the mock server running.
    """
    from src.extractors.immuta_to_ranger import ImmutaExtractor
    from src.mocks.immuta_mock import POLICIES, PERMISSIONS, DATA_SOURCES

    extractor = ImmutaExtractor()
    extractor.immuta_mode = "mock"

    ranger_policies: list[dict[str, Any]] = []
    for policy in POLICIES:
        ranger_policies.extend(extractor._convert_policy(policy))
    ranger_policies.extend(
        extractor._convert_permissions(PERMISSIONS, DATA_SOURCES)
    )

    logger.info("ImmutaExtractor produced %d policies from mock data", len(ranger_policies))
    return ranger_policies


@pytest.fixture(scope="session")
def bedrock_extracted_policies() -> list[dict[str, Any]]:
    """Run BedrockExtractor.extract_policies() and return the results.

    Returns Ranger-format mirror policies for Bedrock models.
    """
    from src.extractors.bedrock_to_ranger import BedrockExtractor

    extractor = BedrockExtractor()
    policies = extractor.extract_policies()
    logger.info("BedrockExtractor produced %d policies", len(policies))
    return policies


# ---------------------------------------------------------------------------
# Multi-identity provisioner (idempotent)
# ---------------------------------------------------------------------------

_PERSONA_MEMBERSHIPS: dict[str, list[str]] = {
    "alice_analyst": ["data_analysts", "na_analysts"],
    "bob_risk": ["risk_investigators"],
    "carol_compliance": ["compliance_officers"],
    "frank_external": ["external_auditors"],
}


def _ensure_ranger_user_exists(
    name: str, base_url: str, auth: tuple[str, str]
) -> int | None:
    """Ensure a Ranger user exists. Returns the user ID or None."""
    try:
        resp = requests.get(
            f"{base_url}/service/xusers/users/userName/{name}",
            auth=auth,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("id")
    except requests.RequestException:
        pass

    user_password = os.getenv("RANGER_USER_DEFAULT_PASSWORD", "")
    try:
        payload = {
            "name": name,
            "firstName": name,
            "lastName": "ext",
            "status": 1,
            "isVisible": 1,
            "userRoleList": ["ROLE_USER"],
            "userSource": 0,
            "password": user_password,
        }
        resp = requests.post(
            f"{base_url}/service/xusers/secure/users",
            json=payload,
            auth=auth,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info("Created Ranger user: %s", name)
            return resp.json().get("id")
        logger.warning(
            "Could not create Ranger user '%s': %s %s",
            name, resp.status_code, resp.text[:200],
        )
    except requests.RequestException as exc:
        logger.warning("Failed to create Ranger user '%s': %s", name, exc)
    return None


def _ensure_ranger_group_exists(
    name: str, base_url: str, auth: tuple[str, str]
) -> int | None:
    """Ensure a Ranger group exists. Returns the group ID or None."""
    try:
        resp = requests.get(
            f"{base_url}/service/xusers/groups/groupName/{name}",
            auth=auth,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json().get("id")
    except requests.RequestException:
        pass

    try:
        payload = {
            "name": name,
            "description": f"Provisioned for multi-identity tests",
            "groupType": 0,
            "groupSource": 0,
            "isVisible": 1,
        }
        resp = requests.post(
            f"{base_url}/service/xusers/secure/groups",
            json=payload,
            auth=auth,
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info("Created Ranger group: %s", name)
            return resp.json().get("id")
        logger.warning(
            "Could not create Ranger group '%s': %s %s",
            name, resp.status_code, resp.text[:200],
        )
    except requests.RequestException as exc:
        logger.warning("Failed to create Ranger group '%s': %s", name, exc)
    return None


def _provision_user_groups(
    user: str,
    groups: list[str],
    base_url: str,
    auth: tuple[str, str],
) -> None:
    """Set a user's group memberships via PUT (idempotent).

    Ranger 2.x groupusers POST returns 404 — use the secure users PUT
    endpoint with groupIdList instead.
    """
    user_id = _ensure_ranger_user_exists(user, base_url, auth)
    if user_id is None:
        logger.warning("Cannot provision groups for %s: user not found", user)
        return

    group_ids: list[int] = []
    for group in groups:
        gid = _ensure_ranger_group_exists(group, base_url, auth)
        if gid is not None:
            group_ids.append(gid)
        else:
            logger.warning("Cannot add %s to group %s: group not found", user, group)

    if not group_ids:
        return

    # Check current memberships
    try:
        resp = requests.get(
            f"{base_url}/service/xusers/users/userName/{user}",
            auth=auth,
            timeout=15,
        )
        if resp.status_code == 200:
            current = set(resp.json().get("groupIdList", []))
            if set(group_ids).issubset(current):
                logger.debug("User %s already in groups %s", user, groups)
                return
    except requests.RequestException:
        pass

    user_password = os.getenv("RANGER_USER_DEFAULT_PASSWORD", "")
    try:
        payload = {
            "id": user_id,
            "name": user,
            "firstName": user,
            "lastName": "ext",
            "status": 1,
            "isVisible": 1,
            "userRoleList": ["ROLE_USER"],
            "userSource": 0,
            "groupIdList": group_ids,
            "password": user_password,
        }
        resp = requests.put(
            f"{base_url}/service/xusers/secure/users/{user_id}",
            json=payload,
            auth=auth,
            timeout=15,
        )
        if resp.status_code == 200:
            assigned = resp.json().get("groupNameList", [])
            logger.info("Set group memberships for %s: %s", user, assigned)
        else:
            logger.warning(
                "Could not set groups for %s: %s %s",
                user, resp.status_code, resp.text[:200],
            )
    except requests.RequestException as exc:
        logger.warning("Failed to set groups for %s: %s", user, exc)


def _add_users_to_policy(
    policy_name: str,
    users: list[str],
    base_url: str,
    auth: tuple[str, str],
) -> None:
    """Add users to the first policyItem of a named Ranger policy (idempotent)."""
    try:
        resp = requests.get(
            f"{base_url}/service/public/v2/api/policy",
            params={"serviceName": "dev_trino", "policyName": policy_name},
            auth=auth,
            timeout=30,
        )
        resp.raise_for_status()
        policies = resp.json()
        if not policies:
            logger.warning("Policy '%s' not found", policy_name)
            return

        policy = policies[0]
        pid = policy["id"]
        items = policy.get("policyItems", [])
        if not items:
            logger.warning("Policy '%s' has no policyItems", policy_name)
            return

        current_users = set(items[0].get("users", []))
        new_users = set(users) - current_users
        if not new_users:
            return

        items[0]["users"] = sorted(current_users | set(users))
        resp = requests.put(
            f"{base_url}/service/public/v2/api/policy/{pid}",
            json=policy,
            auth=auth,
            timeout=30,
        )
        resp.raise_for_status()
        logger.info("Added %s to policy '%s'", sorted(new_users), policy_name)
    except requests.RequestException as exc:
        logger.warning("Failed to update policy '%s': %s", policy_name, exc)


# System-level Ranger policies that persona users need to run queries.
# IMPORTANT: Do NOT include data access policies (catalog, schema, table, column)
# here — those wildcard policies override FGAC masking, row filters, and deny.
# Persona users get table-level access through Immuta-derived subscription policies.
_SYSTEM_POLICIES = [
    "all - trinouser",                     # impersonate (become the user)
    "all - queryid",                        # execute queries
    "all - function",                       # use SQL functions (count, etc.)
]


@pytest.fixture(scope="session")
def _provision_multi_identity(
    ranger_base_url: str, ranger_auth: tuple[str, str]
) -> None:
    """Ensure persona users exist with correct group memberships in Ranger."""
    if not os.getenv("RANGER_HOST", ""):
        pytest.fail("RANGER_HOST not configured")

    persona_users = list(_PERSONA_MEMBERSHIPS.keys())

    # Set group memberships for each persona
    for user, groups in _PERSONA_MEMBERSHIPS.items():
        _provision_user_groups(user, groups, ranger_base_url, ranger_auth)

    # Add persona users to system-level Ranger policies for Trino access
    for policy_name in _SYSTEM_POLICIES:
        _add_users_to_policy(policy_name, persona_users, ranger_base_url, ranger_auth)

    logger.info("Multi-identity provisioning complete: %s", persona_users)


@pytest.fixture(scope="session")
def analyst_trino_conn(_provision_multi_identity: None) -> Iterator[Any]:
    """Trino connection as alice_analyst (data_analysts + na_analysts)."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    if not host:
        pytest.fail("TRINO_HOST not configured")
    port = int(os.getenv("TRINO_PORT", "8080"))
    conn = trino.dbapi.connect(host=host, port=port, user="alice_analyst")
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def risk_investigator_trino_conn(_provision_multi_identity: None) -> Iterator[Any]:
    """Trino connection as bob_risk (risk_investigators)."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    if not host:
        pytest.fail("TRINO_HOST not configured")
    port = int(os.getenv("TRINO_PORT", "8080"))
    conn = trino.dbapi.connect(host=host, port=port, user="bob_risk")
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def compliance_trino_conn(_provision_multi_identity: None) -> Iterator[Any]:
    """Trino connection as carol_compliance (compliance_officers)."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    if not host:
        pytest.fail("TRINO_HOST not configured")
    port = int(os.getenv("TRINO_PORT", "8080"))
    conn = trino.dbapi.connect(host=host, port=port, user="carol_compliance")
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def auditor_trino_conn(_provision_multi_identity: None) -> Iterator[Any]:
    """Trino connection as frank_external (external_auditors)."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    if not host:
        pytest.fail("TRINO_HOST not configured")
    port = int(os.getenv("TRINO_PORT", "8080"))
    conn = trino.dbapi.connect(host=host, port=port, user="frank_external")
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def solr_audit_url() -> str:
    """Return the Solr audit query URL."""
    host = os.getenv("SOLR_HOST", "localhost")
    port = os.getenv("SOLR_PORT", "8983")
    return f"http://{host}:{port}/solr/ranger_audits/select"
