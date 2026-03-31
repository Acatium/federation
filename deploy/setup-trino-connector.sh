#!/usr/bin/env bash
# Download and install the Gravitino Trino connector plugin.
#
# This fetches the gravitino-trino-connector tarball from Apache and extracts
# it into deploy/trino-plugins/ so docker-compose can mount it into Trino.
#
# Usage:
#   bash deploy/setup-trino-connector.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGINS_DIR="${SCRIPT_DIR}/trino-plugins"
GRAVITINO_VERSION="${GRAVITINO_VERSION:-1.1.0}"
CONNECTOR_DIR="gravitino-trino-connector-${GRAVITINO_VERSION}"
TARBALL="${CONNECTOR_DIR}.tar.gz"
DOWNLOAD_URL="https://dlcdn.apache.org/gravitino/${GRAVITINO_VERSION}/${TARBALL}"

mkdir -p "$PLUGINS_DIR"

if [ -d "$PLUGINS_DIR/$CONNECTOR_DIR" ]; then
    echo "[OK] Gravitino Trino connector already installed: $PLUGINS_DIR/$CONNECTOR_DIR"
    exit 0
fi

echo "=== Downloading Gravitino Trino connector ${GRAVITINO_VERSION} ==="
echo "URL: $DOWNLOAD_URL"

cd /tmp
if curl -fSL --progress-bar -o "$TARBALL" "$DOWNLOAD_URL"; then
    echo "[OK] Downloaded $TARBALL"
else
    echo "[ERROR] Failed to download from $DOWNLOAD_URL"
    echo "Check https://gravitino.apache.org/downloads/ for available versions."
    exit 1
fi

# SHA-256 verification — download checksum from Apache and verify
echo "=== Verifying SHA-256 checksum ==="
SHA256_URL="${DOWNLOAD_URL}.sha256"
if curl -fsSL -o "${TARBALL}.sha256" "$SHA256_URL" 2>/dev/null; then
    EXPECTED_SHA256=$(awk '{print $1}' "${TARBALL}.sha256")
    ACTUAL_SHA256=$(sha256sum "$TARBALL" | awk '{print $1}')
    if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
        echo "[FATAL] SHA-256 checksum mismatch — download may be corrupted or tampered"
        echo "  Expected: $EXPECTED_SHA256"
        echo "  Actual:   $ACTUAL_SHA256"
        rm -f "$TARBALL" "${TARBALL}.sha256"
        exit 1
    fi
    echo "[OK] Checksum verified"
    rm -f "${TARBALL}.sha256"
else
    echo "[WARN] Could not download checksum file from $SHA256_URL — skipping verification"
fi

echo "=== Extracting connector ==="
tar xzf "$TARBALL"
mv "$CONNECTOR_DIR" "$PLUGINS_DIR/"
rm -f "$TARBALL"

echo "=== Installed ==="
ls -la "$PLUGINS_DIR/$CONNECTOR_DIR/"
echo ""
echo "Connector installed to: $PLUGINS_DIR/$CONNECTOR_DIR"
echo "Docker Compose will mount this into Trino at /lib/trino/plugin/gravitino"
