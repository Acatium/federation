#!/usr/bin/env bash
# Provision the federation demo: register catalogs, load data, push policies.
#
# Run AFTER docker-compose is up and all services are healthy.
# Run FROM the project root (not from deploy/).
#
# Usage:
#   source .venv/bin/activate
#   bash deploy/provision.sh
#
# Prerequisites:
#   - Docker stack running (deploy/docker-compose.yml)
#   - .env configured with all credentials
#   - Python venv with deps installed (pip install -e '.[dev,demo]')

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Load environment
set -a
source .env
set +a

# S4: Verify .env has restrictive permissions
ENV_PERMS=$(stat -c %a .env 2>/dev/null || stat -f %Lp .env 2>/dev/null)
if [ "$ENV_PERMS" != "600" ]; then
    echo "  [WARN] .env has permissions ${ENV_PERMS}, expected 600. Run: chmod 600 .env"
fi

GRAVITINO_URL="http://${GRAVITINO_HOST}:${GRAVITINO_PORT}"

# ===================================================================
# Helper functions (S1: idempotent, S2: graceful degradation, S3: API detect)
# ===================================================================

# S3: Gravitino tag API version detection — try newer endpoint, fall back to older
associate_tag() {
    local obj_type=$1 obj_name=$2 tag_name=$3
    # Try v1.x format (Gravitino 1.1.0)
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${GRAVITINO_URL}/api/metalakes/federation/objects/${obj_type}/${obj_name}/tags" \
        -H "Content-Type: application/json" \
        -d "{\"tagsToAdd\": [\"${tag_name}\"], \"tagsToRemove\": []}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
        echo "  [OK] Tagged ${obj_type}/${obj_name} with ${tag_name}"
        return 0
    fi
    # Try older format
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${GRAVITINO_URL}/api/metalakes/federation/tags/${obj_type}/${obj_name}" \
        -H "Content-Type: application/json" \
        -d "{\"tagsToAdd\": [\"${tag_name}\"], \"tagsToRemove\": []}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
        echo "  [OK] Tagged ${obj_type}/${obj_name} with ${tag_name} (legacy API)"
        return 0
    fi
    echo "  [WARN] Failed to tag ${obj_type}/${obj_name} (HTTP ${code})"
    return 1
}

# S1: Idempotent Gravitino tag creation (check-before-create)
create_gravitino_tag() {
    local tag_name=$1 comment=$2
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        "${GRAVITINO_URL}/api/metalakes/federation/tags/${tag_name}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        echo "  [EXISTS] tag: ${tag_name}"
        return 0
    fi
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${GRAVITINO_URL}/api/metalakes/federation/tags" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${tag_name}\", \"comment\": \"${comment}\", \"properties\": {}}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
        echo "  [CREATED] tag: ${tag_name}"
        return 0
    fi
    echo "  [WARN] Could not create tag '${tag_name}' (HTTP ${code})"
    return 1
}

# S1: Idempotent Ranger zone creation (check-before-create)
create_ranger_zone() {
    local zone_name=$1 zone_json=$2
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${RANGER_AUTH}" \
        "${RANGER_URL}/service/public/v2/api/zones/name/${zone_name}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        echo "  [EXISTS] zone: ${zone_name}"
        return 0
    fi
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${RANGER_AUTH}" \
        -H "Content-Type: application/json" \
        -X POST "${RANGER_URL}/service/public/v2/api/zones" \
        -d "${zone_json}" 2>/dev/null || echo "000")
    if [ "$code" = "200" ] || [ "$code" = "201" ]; then
        echo "  [CREATED] zone: ${zone_name}"
        return 0
    fi
    echo "  [WARN] Could not create zone '${zone_name}' (HTTP ${code})"
    return 1
}

echo "============================================================"
echo "Federation Demo Provisioning"
echo "  Gravitino: ${GRAVITINO_URL}"
echo "  Ranger:    http://${RANGER_HOST}:${RANGER_PORT}"
echo "  Trino:     http://${TRINO_HOST}:${TRINO_PORT}"
echo "============================================================"
echo ""

# -------------------------------------------------------------------
# 1. Wait for services
# -------------------------------------------------------------------
echo "=== Step 1: Checking service health ==="

check_service() {
    local name="$1" url="$2"
    for i in $(seq 1 30); do
        if curl -sf -o /dev/null "$url" 2>/dev/null; then
            echo "  [OK] $name"
            return 0
        fi
        sleep 2
    done
    echo "  [FAIL] $name not reachable at $url"
    return 1
}

check_service "Gravitino" "${GRAVITINO_URL}/api/version"
check_service "Ranger" "http://${RANGER_HOST}:${RANGER_PORT}/login.jsp"
check_service "Trino" "http://${TRINO_HOST}:${TRINO_PORT}/v1/info"

# Log both Gravitino image tag and API version
GRAVITINO_API_VERSION=$(curl -sf "${GRAVITINO_URL}/api/version" | python3 -c "import sys,json; print(json.load(sys.stdin)['version']['version'])")
echo "  Gravitino API version: ${GRAVITINO_API_VERSION}"
echo "  Gravitino Docker image: apache/gravitino:1.1.0"
echo "  NOTE: API version (${GRAVITINO_API_VERSION}) is the REST API spec version,"
echo "        not the product version. Image tag 1.1.0 is the product version."
echo ""

# -------------------------------------------------------------------
# 2. Verify Ranger enforcement is active
# -------------------------------------------------------------------
echo "=== Step 2: Verifying Ranger enforcement on Trino ==="

# Check Trino logs for Ranger plugin initialization
if docker logs federation-trino 2>&1 | grep -qi "ranger"; then
    echo "  [OK] Ranger plugin loaded in Trino"
else
    echo "  [WARN] Ranger plugin may not be loaded in Trino"
    echo "  Check: docker logs federation-trino 2>&1 | grep -i 'access.control\|ranger\|error'"
    echo "  Trino 479 has a built-in Ranger plugin — check config if not loading."
    echo ""
    echo "  Attempting fallback: file-based access control from Ranger policies..."
    if [ -f deploy/generate-rules-json.sh ]; then
        echo "  Run: bash deploy/generate-rules-json.sh"
        echo "  Then update deploy/trino-config/access-control.properties:"
        echo "    access-control.name=file"
        echo "    security.config-file=/etc/trino/rules.json"
    fi
    echo ""
    echo "  Continuing with provisioning (enforcement may be incomplete)..."
fi
echo ""

# -------------------------------------------------------------------
# 2b. Create Ranger service definition for Trino
# -------------------------------------------------------------------
echo "=== Step 2b: Creating Ranger Trino service definition ==="

RANGER_URL="http://${RANGER_HOST}:${RANGER_PORT}"
RANGER_AUTH="${RANGER_ADMIN_USER:-admin}:${RANGER_ADMIN_PASSWORD}"

# The Ranger 2.7.0 image ships with the 'trino' service TYPE built-in,
# but the service INSTANCE must be created explicitly.
SVC_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    -u "${RANGER_AUTH}" \
    "${RANGER_URL}/service/public/v2/api/service/name/${RANGER_SERVICE:-dev_trino}" 2>/dev/null || echo "000")

if [ "$SVC_CODE" = "200" ]; then
    echo "  [EXISTS] Ranger service '${RANGER_SERVICE:-dev_trino}' already exists"
else
    SVC_CREATE_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
        -u "${RANGER_AUTH}" \
        -H "Content-Type: application/json" \
        -X POST "${RANGER_URL}/service/public/v2/api/service" \
        -d "{
            \"name\": \"${RANGER_SERVICE:-dev_trino}\",
            \"type\": \"trino\",
            \"description\": \"Federation demo Trino instance\",
            \"isEnabled\": true,
            \"configs\": {
                \"username\": \"trino\",
                \"password\": \"\",
                \"jdbc.driverClassName\": \"io.trino.jdbc.TrinoDriver\",
                \"jdbc.url\": \"jdbc:trino://trino:8080\"
            }
        }" 2>/dev/null || echo "000")

    if [ "$SVC_CREATE_CODE" = "200" ] || [ "$SVC_CREATE_CODE" = "201" ]; then
        echo "  [CREATED] Ranger service '${RANGER_SERVICE:-dev_trino}'"
    else
        echo "  [WARN] Could not create Ranger service (HTTP ${SVC_CREATE_CODE})"
        echo "  Policy pushes may fail if service does not exist."
    fi
fi
echo ""

# -------------------------------------------------------------------
# 3. Provision Ranger test users
# -------------------------------------------------------------------
echo "=== Step 3: Provisioning Ranger test users ==="

create_ranger_user() {
    local username="$1"
    local password="${RANGER_USER_DEFAULT_PASSWORD:-${RANGER_ADMIN_PASSWORD}}"

    # Check if user exists
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" \
        -u "${RANGER_AUTH}" \
        "${RANGER_URL}/service/xusers/users/userName/${username}" 2>/dev/null || echo "000")

    if [ "$status" = "200" ]; then
        echo "  [OK] User '${username}' already exists"
        return 0
    fi

    # Create user
    local resp_code
    resp_code=$(curl -sf -o /dev/null -w "%{http_code}" \
        -u "${RANGER_AUTH}" \
        -H "Content-Type: application/json" \
        -X POST "${RANGER_URL}/service/xusers/secure/users" \
        -d "{
            \"name\": \"${username}\",
            \"firstName\": \"${username}\",
            \"lastName\": \"test\",
            \"status\": 1,
            \"isVisible\": 1,
            \"userRoleList\": [\"ROLE_USER\"],
            \"userSource\": 0,
            \"password\": \"${password}\"
        }" 2>/dev/null || echo "000")

    if [ "$resp_code" = "200" ] || [ "$resp_code" = "201" ]; then
        echo "  [OK] Created user '${username}'"
    else
        echo "  [WARN] Could not create user '${username}' (HTTP ${resp_code})"
    fi
}

create_ranger_user "test_user"
create_ranger_user "restricted_user"

# Create policy for test_user (SELECT on all demo tables)
echo "  Creating test_user access policy..."
TEST_POLICY_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    -u "${RANGER_AUTH}" \
    -H "Content-Type: application/json" \
    -X POST "${RANGER_URL}/service/public/v2/api/policy" \
    -d "{
        \"policyType\": 0,
        \"service\": \"${RANGER_SERVICE:-dev_trino}\",
        \"name\": \"test_user_demo_access\",
        \"isEnabled\": true,
        \"resources\": {
            \"catalog\": {\"values\": [\"hive\"]},
            \"schema\": {\"values\": [\"federation_demo\"]},
            \"table\": {\"values\": [\"*\"]},
            \"column\": {\"values\": [\"*\"]}
        },
        \"policyItems\": [{
            \"users\": [\"test_user\"],
            \"groups\": [],
            \"accesses\": [{\"type\": \"select\", \"isAllowed\": true}]
        }],
        \"policyLabels\": [\"source:provision\", \"purpose:testing\"]
    }" 2>/dev/null || echo "000")

if [ "$TEST_POLICY_CODE" = "200" ] || [ "$TEST_POLICY_CODE" = "201" ]; then
    echo "  [OK] test_user access policy created"
elif [ "$TEST_POLICY_CODE" = "400" ]; then
    echo "  [OK] test_user access policy already exists"
else
    echo "  [WARN] test_user policy creation returned HTTP ${TEST_POLICY_CODE}"
fi

echo "  NOTE: restricted_user has NO policies — access should be denied"
echo ""

# -------------------------------------------------------------------
# 3b. Register Hive catalog in Gravitino (Glue Data Catalog backend)
# -------------------------------------------------------------------
echo "=== Step 3b: Registering hive catalog in Gravitino ==="

HIVE_PAYLOAD=$(cat <<HIVEJSON
{
  "name": "hive",
  "type": "RELATIONAL",
  "provider": "lakehouse-iceberg",
  "comment": "Warm tier via Glue Data Catalog (Hive-compatible tables)",
  "properties": {
    "catalog-backend": "custom",
    "gravitino.bypass.catalog-backend-impl": "org.apache.iceberg.aws.glue.GlueCatalog",
    "uri": "https://glue.${AWS_REGION}.amazonaws.com",
    "warehouse": "s3://${S3_BUCKET}/warehouse/",
    "gravitino.bypass.io-impl": "org.apache.iceberg.aws.s3.S3FileIO",
    "gravitino.bypass.glue.id": "${AWS_ACCOUNT_ID}",
    "gravitino.bypass.glue.region": "${AWS_REGION}",
    "s3-access-key-id": "${AWS_ACCESS_KEY_ID}",
    "s3-secret-access-key": "${AWS_SECRET_ACCESS_KEY}",
    "s3-region": "${AWS_REGION}",
    "governance_tier": "platform_native",
    "trino.bypass.iceberg.security": "SYSTEM"
  }
}
HIVEJSON
)

HIVE_CODE=$(curl -sf -o /tmp/gravitino-hive-resp.json -w "%{http_code}" \
    -X POST "${GRAVITINO_URL}/api/metalakes/federation/catalogs" \
    -H "Content-Type: application/json" \
    -d "$HIVE_PAYLOAD" 2>/dev/null || echo "000")

if [ "$HIVE_CODE" = "200" ] || [ "$HIVE_CODE" = "201" ]; then
    echo "  [OK] hive catalog created"
elif [ "$HIVE_CODE" = "409" ]; then
    echo "  [OK] hive catalog already exists"
else
    echo "  [WARN] hive registration returned HTTP $HIVE_CODE"
    cat /tmp/gravitino-hive-resp.json 2>/dev/null || true
    echo ""
fi
echo ""

# -------------------------------------------------------------------
# 4. Register Iceberg catalog in Gravitino
# -------------------------------------------------------------------
echo "=== Step 4: Registering iceberg_s3 catalog in Gravitino ==="

ICEBERG_PAYLOAD=$(cat <<ICEJSON
{
  "name": "iceberg_s3",
  "type": "RELATIONAL",
  "provider": "lakehouse-iceberg",
  "comment": "S3 Iceberg cold tier (Lake Formation + IAM governed)",
  "properties": {
    "catalog-backend": "custom",
    "gravitino.bypass.catalog-backend-impl": "org.apache.iceberg.aws.glue.GlueCatalog",
    "uri": "https://glue.${AWS_REGION}.amazonaws.com",
    "warehouse": "s3://${S3_BUCKET}/iceberg/",
    "gravitino.bypass.io-impl": "org.apache.iceberg.aws.s3.S3FileIO",
    "gravitino.bypass.glue.id": "${AWS_ACCOUNT_ID}",
    "gravitino.bypass.glue.region": "${AWS_REGION}",
    "s3-access-key-id": "${AWS_ACCESS_KEY_ID}",
    "s3-secret-access-key": "${AWS_SECRET_ACCESS_KEY}",
    "s3-region": "${AWS_REGION}",
    "governance_tier": "platform_native",
    "trino.bypass.iceberg.security": "SYSTEM"
  }
}
ICEJSON
)

HTTP_CODE=$(curl -sf -o /tmp/gravitino-iceberg-resp.json -w "%{http_code}" \
    -X POST "${GRAVITINO_URL}/api/metalakes/federation/catalogs" \
    -H "Content-Type: application/json" \
    -d "$ICEBERG_PAYLOAD" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
    echo "  [OK] iceberg_s3 catalog created"
elif [ "$HTTP_CODE" = "409" ]; then
    echo "  [OK] iceberg_s3 catalog already exists"
else
    echo "  [WARN] iceberg_s3 registration returned HTTP $HTTP_CODE"
    cat /tmp/gravitino-iceberg-resp.json 2>/dev/null || true
    echo ""
fi

# -------------------------------------------------------------------
# 5. Register Snowflake catalog in Gravitino (Open Catalog / Iceberg REST)
# -------------------------------------------------------------------
# LIMITATION: Gravitino 1.1.0 has no native Snowflake JDBC catalog provider.
# Its jdbc-postgresql provider uses pg_catalog.pg_namespace queries internally —
# PostgreSQL-specific system tables that Snowflake does not expose.
# Supported JDBC providers: MySQL, PostgreSQL, Doris, OceanBase, StarRocks only.
#
# Instead, we use Snowflake Open Catalog (managed Polaris), which exposes tables
# via the Iceberg REST protocol — same architecture as Databricks Unity Catalog.
# Snowflake data remains queryable directly via Trino's native Snowflake connector.
echo "=== Step 5: Registering Snowflake catalog in Gravitino (Open Catalog IRC) ==="

if [ -n "${SNOWFLAKE_OPEN_CATALOG_ACCOUNT:-}" ] && [ -n "${SNOWFLAKE_OPEN_CATALOG_CLIENT_ID:-}" ]; then
    SNOWFLAKE_PAYLOAD=$(cat <<'SNOWJSON'
{
  "name": "snowflake",
  "type": "RELATIONAL",
  "provider": "lakehouse-iceberg",
  "comment": "Snowflake via Open Catalog (Polaris) Iceberg REST",
  "properties": {
    "catalog-backend": "rest",
    "uri": "https://${SNOWFLAKE_OPEN_CATALOG_ACCOUNT}.snowflakecomputing.com/polaris/api/catalog",
    "warehouse": "${SNOWFLAKE_OPEN_CATALOG_CATALOG}",
    "gravitino.bypass.credential": "${SNOWFLAKE_OPEN_CATALOG_CLIENT_ID}:${SNOWFLAKE_OPEN_CATALOG_CLIENT_SECRET}",
    "gravitino.bypass.oauth2-server-uri": "https://${SNOWFLAKE_OPEN_CATALOG_ACCOUNT}.snowflakecomputing.com/polaris/api/catalog/v1/oauth/tokens",
    "gravitino.bypass.scope": "PRINCIPAL_ROLE:ALL",
    "governance_tier": "platform_native",
    "federation_note": "open_catalog_iceberg_rest"
  }
}
SNOWJSON
)
    # Substitute env vars in the payload
    SNOWFLAKE_PAYLOAD=$(echo "$SNOWFLAKE_PAYLOAD" | \
        sed "s|\${SNOWFLAKE_OPEN_CATALOG_ACCOUNT}|${SNOWFLAKE_OPEN_CATALOG_ACCOUNT}|g" | \
        sed "s|\${SNOWFLAKE_OPEN_CATALOG_CATALOG}|${SNOWFLAKE_OPEN_CATALOG_CATALOG:-federation_demo}|g" | \
        sed "s|\${SNOWFLAKE_OPEN_CATALOG_CLIENT_ID}|${SNOWFLAKE_OPEN_CATALOG_CLIENT_ID}|g" | \
        sed "s|\${SNOWFLAKE_OPEN_CATALOG_CLIENT_SECRET}|${SNOWFLAKE_OPEN_CATALOG_CLIENT_SECRET}|g")

    SF_CODE=$(curl -sf -o /tmp/gravitino-snowflake-resp.json -w "%{http_code}" \
        -X POST "${GRAVITINO_URL}/api/metalakes/federation/catalogs" \
        -H "Content-Type: application/json" \
        -d "$SNOWFLAKE_PAYLOAD" 2>/dev/null || echo "000")

    if [ "$SF_CODE" = "200" ] || [ "$SF_CODE" = "201" ]; then
        echo "  [OK] snowflake catalog registered (Open Catalog IRC)"
    elif [ "$SF_CODE" = "409" ]; then
        echo "  [OK] snowflake catalog already exists"
    else
        echo "  [FAIL] snowflake registration returned HTTP $SF_CODE"
        cat /tmp/gravitino-snowflake-resp.json 2>/dev/null || true
        echo ""
    fi
    echo "  NOTE: Snowflake data also queryable via Trino's native Snowflake connector"
else
    echo "  [SKIP] SNOWFLAKE_OPEN_CATALOG_ACCOUNT not configured"
    echo "  To enable: set SNOWFLAKE_OPEN_CATALOG_ACCOUNT, SNOWFLAKE_OPEN_CATALOG_CLIENT_ID,"
    echo "  SNOWFLAKE_OPEN_CATALOG_CLIENT_SECRET, and SNOWFLAKE_OPEN_CATALOG_CATALOG in .env"
fi
echo ""

# -------------------------------------------------------------------
# 5b. Register Databricks catalog in Gravitino (credential vending)
# -------------------------------------------------------------------
echo "=== Step 5b: Registering Databricks catalog in Gravitino ==="

if [ -n "${DATABRICKS_HOST:-}" ] && [ -n "${DATABRICKS_TOKEN:-}" ]; then
    DATABRICKS_PAYLOAD=$(cat <<'DBJSON'
{
  "name": "databricks",
  "type": "RELATIONAL",
  "provider": "lakehouse-iceberg",
  "comment": "Databricks Unity Catalog via Iceberg REST + credential vending",
  "properties": {
    "catalog-backend": "rest",
    "uri": "${DATABRICKS_HOST}/api/2.1/unity-catalog/iceberg-rest",
    "warehouse": "${DATABRICKS_CATALOG}",
    "gravitino.bypass.token": "${DATABRICKS_TOKEN}",
    "governance_tier": "platform_native",
    "federation_note": "credential_vending_preserves_uc_acls"
  }
}
DBJSON
)
    # Substitute env vars in the payload
    DATABRICKS_PAYLOAD=$(echo "$DATABRICKS_PAYLOAD" | \
        sed "s|\${DATABRICKS_HOST}|${DATABRICKS_HOST}|g" | \
        sed "s|\${DATABRICKS_CATALOG}|${DATABRICKS_CATALOG:-main}|g" | \
        sed "s|\${DATABRICKS_TOKEN}|${DATABRICKS_TOKEN}|g")

    DB_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST "${GRAVITINO_URL}/api/metalakes/federation/catalogs" \
        -H "Content-Type: application/json" \
        -d "$DATABRICKS_PAYLOAD" 2>/dev/null || echo "000")

    if [ "$DB_CODE" = "200" ] || [ "$DB_CODE" = "201" ]; then
        echo "  [OK] databricks catalog registered (Iceberg REST + credential vending)"
    elif [ "$DB_CODE" = "409" ]; then
        echo "  [OK] databricks catalog already exists"
    else
        echo "  [INFO] databricks registration returned HTTP $DB_CODE"
    fi
    echo "  NOTE: Databricks data federated via Trino Iceberg REST connector"
    echo "  Safety property: UC validates permissions, vends scoped STS credentials"
else
    echo "  [SKIP] DATABRICKS_HOST not configured"
fi
echo ""

# -------------------------------------------------------------------
# 6. Register Bedrock model catalog in Gravitino
# -------------------------------------------------------------------
echo "=== Step 6: Registering bedrock_models catalog in Gravitino ==="

python3 -c "
from src.models.bedrock_catalog import BedrockModelCatalog
catalog = BedrockModelCatalog()
result = catalog.register_all()
print(f'  Models registered: {result[\"models_registered\"]}')
print(f'  Status: {result[\"status\"]}')
"

# -------------------------------------------------------------------
# 7. Verify catalogs
# -------------------------------------------------------------------
echo ""
echo "=== Step 7: Verifying Gravitino catalogs ==="

python3 -c "
import requests, json
resp = requests.get('${GRAVITINO_URL}/api/metalakes/federation/catalogs', timeout=10)
data = resp.json()
names = [i['name'] for i in data.get('identifiers', [])]
print(f'  Registered catalogs: {names}')
for name in names:
    detail = requests.get('${GRAVITINO_URL}/api/metalakes/federation/catalogs/{}'.format(name), timeout=10)
    info = detail.json().get('catalog', {})
    print(f'    {name}: type={info.get(\"type\")}, provider={info.get(\"provider\", \"n/a\")}')
"

# -------------------------------------------------------------------
# 7b. Create Gravitino governance tags (N4)
# -------------------------------------------------------------------
echo ""
echo "=== Step 7b: Creating Gravitino governance tags ==="

# S2: Graceful degradation — tag creation is an enhancement, not a prerequisite
create_gravitino_tags() {
    create_gravitino_tag "governance_tier_platform_native" \
        "Tier 1: Platform-native governance (Redshift RBAC, Snowflake RBAC, UC ACLs, LF, IAM)"
    create_gravitino_tag "governance_tier_immuta_fgac" \
        "Tier 2: Immuta fine-grained access control (masking, row filtering, purpose-based)"
    create_gravitino_tag "pii" \
        "Contains personally identifiable information"
    create_gravitino_tag "sensitive" \
        "Contains sensitive financial data"
}

create_gravitino_tags || echo "  [WARN] Gravitino tag creation failed — continuing without tags"

# Associate tags with catalogs (inherited by all schemas/tables)
echo ""
echo "=== Step 7c: Associating tags with catalogs ==="

associate_catalog_tags() {
    for catalog in iceberg_s3; do
        associate_tag "CATALOG" "${catalog}" "governance_tier_platform_native" || true
    done

    # PII tags on specific tables (if catalogs have been populated)
    associate_tag "TABLE" "iceberg_s3.federation_demo.ledger_entries" "pii" || true
    associate_tag "TABLE" "iceberg_s3.federation_demo.ledger_entries" "sensitive" || true
}

associate_catalog_tags || echo "  [WARN] Tag association failed — continuing without tag associations"

# -------------------------------------------------------------------
# 7d. Create Ranger Security Zones (N6)
# -------------------------------------------------------------------
echo ""
echo "=== Step 7d: Creating Ranger Security Zones ==="

create_ranger_zones() {
    create_ranger_zone "aws-zone" '{
        "name": "aws-zone",
        "description": "AWS platform resources (Hive/Glue, Iceberg S3)",
        "services": {"'"${RANGER_SERVICE:-dev_trino}"'": {"resources": [{"catalog": {"values": ["hive", "iceberg_s3"]}}]}},
        "adminUsers": [],
        "adminUserGroups": ["aws_admins"],
        "auditUsers": [],
        "auditUserGroups": ["auditors"],
        "tagServices": []
    }'

    create_ranger_zone "redshift-zone" '{
        "name": "redshift-zone",
        "description": "Redshift platform resources",
        "services": {"'"${RANGER_SERVICE:-dev_trino}"'": {"resources": [{"catalog": {"values": ["redshift"]}}]}},
        "adminUsers": [],
        "adminUserGroups": ["redshift_admins"],
        "auditUsers": [],
        "auditUserGroups": ["auditors"],
        "tagServices": []
    }'

    create_ranger_zone "snowflake-zone" '{
        "name": "snowflake-zone",
        "description": "Snowflake platform resources",
        "services": {"'"${RANGER_SERVICE:-dev_trino}"'": {"resources": [{"catalog": {"values": ["snowflake"]}}]}},
        "adminUsers": [],
        "adminUserGroups": ["snowflake_admins"],
        "auditUsers": [],
        "auditUserGroups": ["auditors"],
        "tagServices": []
    }'

    create_ranger_zone "databricks-zone" '{
        "name": "databricks-zone",
        "description": "Databricks Unity Catalog resources",
        "services": {"'"${RANGER_SERVICE:-dev_trino}"'": {"resources": [{"catalog": {"values": ["databricks"]}}]}},
        "adminUsers": [],
        "adminUserGroups": ["databricks_admins"],
        "auditUsers": [],
        "auditUserGroups": ["auditors"],
        "tagServices": []
    }'
}

create_ranger_zones || echo "  [WARN] Ranger zone creation failed — continuing without zones"
echo ""

# -------------------------------------------------------------------
# 8. Upload risk_signals to S3 and register as Hive table
# -------------------------------------------------------------------
echo ""
echo "=== Step 8: Uploading risk_signals data to S3 ==="

python3 -c "
import logging, os
from dotenv import load_dotenv
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(name)s %(levelname)s %(message)s')

from src.loaders.generate_and_load import save_local_parquet
from src.loaders.schemas import generate_risk_signals

# Generate risk_signals and save to local Parquet
risk_df = generate_risk_signals()
save_local_parquet(risk_df, 'risk_signals')
print(f'  Risk signals generated: {risk_df.height} rows')

# Upload to S3 if bucket is configured
bucket = os.getenv('S3_BUCKET', '')
if bucket:
    import boto3
    s3 = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'us-east-2'))
    local_path = 'data/parquet/risk_signals.parquet'
    s3_key = 'federation-demo/risk_signals/risk_signals.parquet'
    try:
        s3.upload_file(local_path, bucket, s3_key)
        print(f'  [OK] Uploaded to s3://{bucket}/{s3_key}')
    except Exception as e:
        print(f'  [WARN] S3 upload failed: {e}')
else:
    print('  [SKIP] S3_BUCKET not configured — data saved locally only')
"

# -------------------------------------------------------------------
# 9. Load Iceberg cold tier data to S3
# -------------------------------------------------------------------
echo ""
echo "=== Step 9: Loading Iceberg cold tier data ==="

python3 -c "
import logging, os
from datetime import date
from dotenv import load_dotenv
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(name)s %(levelname)s %(message)s')

from src.loaders.generate_and_load import (
    generate_counterparty_ref, generate_ledger_entries,
    load_iceberg_cold, save_local_parquet,
    HOT_ROWS, WARM_ROWS, COLD_ROWS,
)
from src.utils.config import DATA_SEED, COLD_SEED_OFFSET

# Generate counterparty IDs for FK
cp_df = generate_counterparty_ref()
cp_ids = cp_df['counterparty_id'].to_list()

# Generate cold tier
cold_df = generate_ledger_entries(
    cp_ids,
    n_rows=COLD_ROWS,
    date_start=date(2018, 1, 1),
    date_end=date(2019, 12, 31),
    seed=DATA_SEED + COLD_SEED_OFFSET,
    id_offset=HOT_ROWS + WARM_ROWS,
)
save_local_parquet(cold_df, 'ledger_entries_cold')

result = load_iceberg_cold(cold_df)
print(f'  Cold tier loaded: {result}')
"

# -------------------------------------------------------------------
# 10. Push policies to Ranger (Iceberg gap-fill + Bedrock mirror)
# -------------------------------------------------------------------
echo ""
echo "=== Step 10: Pushing Iceberg gap-fill + Bedrock mirror policies to Ranger ==="

python3 -c "
import logging
logging.basicConfig(level=logging.INFO, format='%(name)s %(levelname)s %(message)s')

from src.extractors.iceberg_gap_fill import IcebergGapFillExtractor
from src.extractors.bedrock_to_ranger import BedrockExtractor

ice_ext = IcebergGapFillExtractor()
ice_result = ice_ext.extract_and_push()
print(f'  Iceberg gap-fill: {ice_result[\"policies_pushed\"]} pushed, {ice_result[\"policies_failed\"]} failed')

bed_ext = BedrockExtractor()
bed_result = bed_ext.extract_and_push()
print(f'  Bedrock mirror: {bed_result[\"policies_pushed\"]} pushed, {bed_result[\"policies_failed\"]} failed')
"

# -------------------------------------------------------------------
# 10b. Create Ranger tag definitions and tag-based policies (N5)
# -------------------------------------------------------------------
echo ""
echo "=== Step 10b: Creating Ranger tag definitions and tag-based policies ==="

create_tag_based_policies() {
    python3 -c "
import logging
logging.basicConfig(level=logging.INFO, format='%(name)s %(levelname)s %(message)s')

from src.extractors.ranger_tag_setup import RangerTagSetup

setup = RangerTagSetup()
result = setup.setup_tags_and_policies()
print(f'  Tag definitions created: {result[\"tags_created\"]}')
print(f'  Tag-based policies created: {result[\"policies_created\"]}')
"
}

create_tag_based_policies || echo "  [WARN] Tag-based policy creation failed — continuing"
echo ""

# -------------------------------------------------------------------
# 11. Download Spark connector JARs
# -------------------------------------------------------------------
echo ""
echo "=== Step 11: Downloading Spark connector JARs ==="

bash deploy/download-spark-connector.sh

# -------------------------------------------------------------------
# 12. Verify Trino can see the Iceberg catalog
# -------------------------------------------------------------------
echo ""
echo "=== Step 12: Verifying Trino sees Iceberg catalog ==="

python3 -c "
import trino, os
conn = trino.dbapi.connect(
    host=os.getenv('TRINO_HOST'),
    port=int(os.getenv('TRINO_PORT', '8080')),
    user=os.getenv('TRINO_USER', 'test_user'),
)
cur = conn.cursor()
cur.execute('SHOW CATALOGS')
catalogs = [r[0] for r in cur.fetchall()]
print(f'  Trino catalogs: {catalogs}')
if 'iceberg_s3' in catalogs:
    print('  [OK] iceberg_s3 visible in Trino')
else:
    print('  [WARN] iceberg_s3 not yet visible — Trino may need a restart')
conn.close()
"

echo ""
echo "============================================================"
echo "Provisioning complete."
echo ""
echo "Architecture:"
echo "  - Trino 479 with direct catalog connectors and built-in Ranger plugin"
echo "  - Hive/Iceberg catalogs use AWS Glue Data Catalog (no HMS dependency)"
echo "  - Snowflake: Open Catalog (Polaris) IRC in Gravitino + native Trino connector"
echo "  - Databricks: UC Iceberg REST + credential vending (UC ACLs preserved)"
echo ""
echo "Three Access Patterns:"
echo "  - Discover: metadata visibility (Gravitino + platform catalog ACLs)"
echo "  - Query: SQL execution (Ranger at Trino; source RBAC for direct)"
echo "  - Access: scoped credentials (platform validates, vends temp creds)"
echo ""
echo "Run: pytest tests/ -v --tb=short"
echo "============================================================"
