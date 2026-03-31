#!/usr/bin/env bash
# Download extra JARs for the Gravitino Iceberg catalog plugin.
#
# The iceberg-aws-bundle JAR enables Gravitino to use AWS Glue Data Catalog
# as an Iceberg catalog backend via the GlueCatalog class.
#
# These JARs are volume-mounted into the Gravitino container at startup
# (see docker-compose.yml gravitino.volumes and entrypoint).
#
# Usage:
#   bash deploy/download-gravitino-jars.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBS_DIR="${SCRIPT_DIR}/gravitino-libs"
mkdir -p "$LIBS_DIR"

ICEBERG_VERSION="${ICEBERG_VERSION:-1.7.1}"
MAVEN_BASE="https://repo1.maven.org/maven2"

JAR_NAME="iceberg-aws-bundle-${ICEBERG_VERSION}.jar"
JAR_URL="${MAVEN_BASE}/org/apache/iceberg/iceberg-aws-bundle/${ICEBERG_VERSION}/${JAR_NAME}"

if [ -f "${LIBS_DIR}/${JAR_NAME}" ]; then
    echo "[OK] ${JAR_NAME} already downloaded"
    ls -lh "${LIBS_DIR}/${JAR_NAME}"
    exit 0
fi

echo "[DOWNLOAD] ${JAR_NAME} -> ${LIBS_DIR}/${JAR_NAME}"
if curl -fSL --progress-bar -o "${LIBS_DIR}/${JAR_NAME}.tmp" "${JAR_URL}"; then
    mv "${LIBS_DIR}/${JAR_NAME}.tmp" "${LIBS_DIR}/${JAR_NAME}"
    echo "[OK] ${JAR_NAME} downloaded successfully"
    ls -lh "${LIBS_DIR}/${JAR_NAME}"
else
    rm -f "${LIBS_DIR}/${JAR_NAME}.tmp"
    echo "[FATAL] Failed to download ${JAR_NAME}"
    exit 1
fi
