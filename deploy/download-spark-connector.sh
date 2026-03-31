#!/usr/bin/env bash
# Download Iceberg Spark runtime JARs for PySpark tests.
#
# These JARs enable PySpark to query Iceberg tables via native GlueCatalog.
# The Gravitino Spark connector is intentionally excluded (bug #6035).
#
# Usage:
#   bash deploy/download-spark-connector.sh

set -euo pipefail

JARS_DIR="$(cd "$(dirname "$0")/.." && pwd)/jars"
mkdir -p "$JARS_DIR"

ICEBERG_VERSION="${ICEBERG_VERSION:-1.7.1}"
HADOOP_VERSION="${HADOOP_VERSION:-3.3.4}"
SPARK_COMPAT="3.5"
SCALA_COMPAT="2.12"

ICEBERG_JAR="iceberg-spark-runtime-${SPARK_COMPAT}_${SCALA_COMPAT}-${ICEBERG_VERSION}.jar"
ICEBERG_AWS_JAR="iceberg-aws-bundle-${ICEBERG_VERSION}.jar"
HADOOP_AWS_JAR="hadoop-aws-${HADOOP_VERSION}.jar"
AWS_SDK_JAR="aws-java-sdk-bundle-1.12.262.jar"

MAVEN_BASE="https://repo1.maven.org/maven2"

# Iceberg Spark runtime
ICEBERG_URL="${MAVEN_BASE}/org/apache/iceberg/iceberg-spark-runtime-${SPARK_COMPAT}_${SCALA_COMPAT}/${ICEBERG_VERSION}/${ICEBERG_JAR}"

# Iceberg AWS bundle (S3FileIO + Glue catalog support for Spark)
ICEBERG_AWS_URL="${MAVEN_BASE}/org/apache/iceberg/iceberg-aws-bundle/${ICEBERG_VERSION}/${ICEBERG_AWS_JAR}"

# Hadoop AWS (S3AFileSystem for spark.read.parquet("s3a://..."))
HADOOP_AWS_URL="${MAVEN_BASE}/org/apache/hadoop/hadoop-aws/${HADOOP_VERSION}/${HADOOP_AWS_JAR}"

# AWS SDK bundle (required by hadoop-aws)
AWS_SDK_URL="${MAVEN_BASE}/com/amazonaws/aws-java-sdk-bundle/1.12.262/${AWS_SDK_JAR}"

download_jar() {
    local url="$1"
    local dest="$2"
    local name="$3"

    if [ -f "$dest" ]; then
        echo "[OK] $name already downloaded: $dest"
        return 0
    fi

    echo "[DOWNLOAD] $name -> $dest"
    if curl -fSL --progress-bar -o "$dest.tmp" "$url"; then
        # SHA-256 verification — Maven publishes .sha1 files; try .sha256 first
        local sha_url="${url}.sha256"
        if curl -fsSL -o "$dest.tmp.sha256" "$sha_url" 2>/dev/null; then
            local expected actual
            expected=$(awk '{print $1}' "$dest.tmp.sha256")
            actual=$(sha256sum "$dest.tmp" | awk '{print $1}')
            rm -f "$dest.tmp.sha256"
            if [ "$actual" != "$expected" ]; then
                echo "[FATAL] SHA-256 checksum mismatch for $name"
                echo "  Expected: $expected"
                echo "  Actual:   $actual"
                rm -f "$dest.tmp"
                return 1
            fi
            echo "[OK] Checksum verified for $name"
        else
            echo "[INFO] No .sha256 available for $name — skipping checksum verification"
        fi
        mv "$dest.tmp" "$dest"
        echo "[OK] $name downloaded successfully"
    else
        rm -f "$dest.tmp"
        echo "[WARN] Failed to download $name from $url"
        echo "       Tests requiring Spark will be skipped."
        return 1
    fi
}

echo "=== Downloading Spark connector JARs to ${JARS_DIR} ==="
echo ""

download_jar "$ICEBERG_URL" "$JARS_DIR/$ICEBERG_JAR" "Iceberg Spark Runtime ${ICEBERG_VERSION}" || true
download_jar "$ICEBERG_AWS_URL" "$JARS_DIR/$ICEBERG_AWS_JAR" "Iceberg AWS Bundle ${ICEBERG_VERSION}" || true
download_jar "$HADOOP_AWS_URL" "$JARS_DIR/$HADOOP_AWS_JAR" "Hadoop AWS ${HADOOP_VERSION}" || true
download_jar "$AWS_SDK_URL" "$JARS_DIR/$AWS_SDK_JAR" "AWS Java SDK Bundle" || true

echo ""
echo "=== JAR directory contents ==="
ls -lh "$JARS_DIR"/*.jar 2>/dev/null || echo "No JARs downloaded."
echo ""
echo "Set SPARK_JARS_DIR=$JARS_DIR in .env if needed."
