#!/bin/bash
set -euo pipefail

# Federation Demo - EC2 Bootstrap Script
#
# Deploys the federation stack (Gravitino + Ranger + Trino) on Amazon Linux 2023.
# Tested on r6i.xlarge (4 vCPU, 32 GB RAM).
#
# Uses the canonical deploy/docker-compose.yml from the repository rather than
# embedding an inline copy. This eliminates drift between the two files.
#
# Required environment variables (set via EC2 user-data or SSM Parameter Store):
#   MYSQL_ROOT_PASSWORD      — MySQL root password for Gravitino backend
#   MYSQL_PASSWORD           — MySQL gravitino user password
#   RANGER_DB_PASSWORD       — PostgreSQL password for Ranger backend
#
# Optional (for Trino access via AWS creds):
#   AWS_ACCESS_KEY_ID        — AWS access key for Trino S3/Glue access
#   AWS_SECRET_ACCESS_KEY    — AWS secret key
#   AWS_REGION               — AWS region (default: us-east-2)
#
# Versions:
#   Gravitino 1.1.0, Ranger 2.7.0, Trino 479
#   Ranger 2.7.0 is required (2.4.0 only ships arm64 Docker images).
#   Trino 479 with direct catalog connectors and built-in Ranger plugin.

exec > /var/log/federation-setup.log 2>&1

echo "=== Federation Stack Setup Starting ==="
date

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------
: "${MYSQL_ROOT_PASSWORD:?MYSQL_ROOT_PASSWORD must be set}"
: "${MYSQL_PASSWORD:?MYSQL_PASSWORD must be set}"
: "${RANGER_DB_PASSWORD:?RANGER_DB_PASSWORD must be set}"

# Optional AWS credentials
AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
AWS_REGION="${AWS_REGION:-us-east-2}"

# Install Docker and Git
dnf update -y
dnf install -y docker git
systemctl enable docker
systemctl start docker

# Install Docker Compose v2
mkdir -p /usr/local/lib/docker/cli-plugins
COMPOSE_VERSION="v2.24.5"
curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-x86_64" \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
docker compose version

# ---------------------------------------------------------------------------
# Clone repository (sparse checkout — deploy/ directory only)
# ---------------------------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/your-org/federation.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"

echo "=== Cloning deploy/ from ${REPO_URL} (branch: ${REPO_BRANCH}) ==="
mkdir -p /opt/federation
cd /opt/federation

if [ -d ".git" ]; then
    echo "Repository already cloned — pulling latest"
    git pull origin "$REPO_BRANCH" || true
else
    git clone --depth 1 --filter=blob:none --sparse \
        --branch "$REPO_BRANCH" "$REPO_URL" .
    git sparse-checkout set deploy/
fi

# ---------------------------------------------------------------------------
# Generate .env and derived configs
# ---------------------------------------------------------------------------
cat > .env << ENVEOF
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_PASSWORD=${MYSQL_PASSWORD}
RANGER_DB_PASSWORD=${RANGER_DB_PASSWORD}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
AWS_REGION=${AWS_REGION}
ENVEOF
chmod 600 .env

# Generate Ranger DB init SQL from template
sed "s/CHANGEME_RANGER_DB_PASSWORD/${RANGER_DB_PASSWORD}/g" \
    deploy/init-ranger-db.sql.template > deploy/init-ranger-db.generated.sql

# ---------------------------------------------------------------------------
# Download plugins
# ---------------------------------------------------------------------------
echo "=== Downloading connector plugins ==="
bash deploy/setup-trino-connector.sh
bash deploy/download-ranger-plugin.sh || echo "[WARN] Ranger plugin download failed — will use fallback"

# ---------------------------------------------------------------------------
# Pull images and start stack
# ---------------------------------------------------------------------------
echo "=== Pulling Docker images ==="
docker pull mysql:8.0 &
docker pull postgres:15 &
docker pull solr:8.11 &
docker pull apache/gravitino:1.1.0 &
docker pull apache/ranger:2.7.0 &
docker pull trinodb/trino:479 &
wait
echo "=== All images pulled ==="

echo "=== Starting federation stack ==="
docker compose --env-file .env -f deploy/docker-compose.yml up -d

# Wait for healthy status
echo "=== Waiting for services to become healthy ==="
echo "Note: Ranger takes ~3 minutes on first start"
docker compose -f deploy/docker-compose.yml ps

# Write completion marker
echo "FEDERATION_SETUP_COMPLETE" > /opt/federation/setup-complete
date >> /opt/federation/setup-complete

echo "=== Federation Stack Setup Complete ==="
date
