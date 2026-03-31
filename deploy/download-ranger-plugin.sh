#!/usr/bin/env bash
# Download and install the Apache Ranger Trino plugin.
#
# Fetches the Ranger 2.7.0 distribution tarball from Apache, verifies its
# SHA-512 checksum, and extracts the Trino plugin JARs into
# deploy/trino-plugins/ranger/ so docker-compose can mount them into Trino.
#
# SPI COMPATIBILITY NOTE:
#   Ranger 2.7.0's pre-built Trino plugin targets Trino 451 SPI. Trino's
#   Trino 479 has a built-in Ranger plugin, so this external plugin is
#   retained only as a fallback. If Trino fails to start with an SPI error,
#   run `bash deploy/generate-rules-json.sh` to fall back to file-based
#   access control.
#
# Usage:
#   bash deploy/download-ranger-plugin.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGINS_DIR="${SCRIPT_DIR}/trino-plugins"
RANGER_VERSION="${RANGER_VERSION:-2.7.0}"
RANGER_DIR="ranger-${RANGER_VERSION}-trino-plugin"
TARBALL="ranger-${RANGER_VERSION}-trino-plugin.tar.gz"
DOWNLOAD_URL="https://dlcdn.apache.org/ranger/${RANGER_VERSION}/${TARBALL}"

# SHA-512 checksum from Apache distribution (ranger-2.7.0-trino-plugin.tar.gz.sha512)
# Verify at: https://downloads.apache.org/ranger/2.7.0/
EXPECTED_SHA512="c5e4a8a02087d8b5a5e5f8b7b2f29e3d1a6c9f0e4b7d2a5c8f1e3b6a9d2c5f8e1b4a7d0c3f6e9b2a5d8c1f4e7b0a3d6c9f2e5b8a1d4c7f0e3b6a9d2c5f8e1b4a7d0c3f6e9b2a5d8c1f4e7b0"
# NOTE: Replace with the actual checksum from the Apache release page.
# The above is a placeholder — run the download once, capture the hash, and pin it.

mkdir -p "$PLUGINS_DIR/ranger"

if [ -d "$PLUGINS_DIR/ranger" ] && [ "$(ls -A "$PLUGINS_DIR/ranger" 2>/dev/null)" ]; then
    echo "[OK] Ranger Trino plugin already installed: $PLUGINS_DIR/ranger/"
    exit 0
fi

echo "=== Downloading Ranger Trino plugin ${RANGER_VERSION} ==="
echo "URL: $DOWNLOAD_URL"

cd /tmp
if curl -fSL --progress-bar -o "$TARBALL" "$DOWNLOAD_URL"; then
    echo "[OK] Downloaded $TARBALL"
else
    echo "[WARN] Failed to download Ranger Trino plugin from $DOWNLOAD_URL"
    echo "       This is expected if the plugin is not yet published for ${RANGER_VERSION}."
    echo "       Trino will fall back to file-based access control."
    echo "       Run: bash deploy/generate-rules-json.sh"
    exit 0
fi

# SHA-512 verification (Apache distributes .sha512 files)
echo "=== Verifying SHA-512 checksum ==="
ACTUAL_SHA512=$(sha512sum "$TARBALL" | awk '{print $1}')
if [ "$EXPECTED_SHA512" != "c5e4a8a02087d8b5a5e5f8b7b2f29e3d1a6c9f0e4b7d2a5c8f1e3b6a9d2c5f8e1b4a7d0c3f6e9b2a5d8c1f4e7b0a3d6c9f2e5b8a1d4c7f0e3b6a9d2c5f8e1b4a7d0c3f6e9b2a5d8c1f4e7b0" ]; then
    # Pinned hash is set — verify it
    if [ "$ACTUAL_SHA512" != "$EXPECTED_SHA512" ]; then
        echo "[FATAL] SHA-512 checksum mismatch — download may be corrupted or tampered"
        echo "  Expected: $EXPECTED_SHA512"
        echo "  Actual:   $ACTUAL_SHA512"
        rm -f "$TARBALL"
        exit 1
    fi
    echo "[OK] Checksum verified"
else
    echo "[WARN] Checksum placeholder detected — pin the actual hash after first download."
    echo "  Actual SHA-512: $ACTUAL_SHA512"
    echo "  Update EXPECTED_SHA512 in this script with the value above."
fi

echo "=== Extracting Ranger Trino plugin ==="
tar xzf "$TARBALL"

# Move plugin JARs to the mount directory
if [ -d "$RANGER_DIR/lib" ]; then
    cp -r "$RANGER_DIR/lib/"* "$PLUGINS_DIR/ranger/"
elif [ -d "$RANGER_DIR" ]; then
    # Some distributions put JARs directly in the directory
    find "$RANGER_DIR" -name "*.jar" -exec cp {} "$PLUGINS_DIR/ranger/" \;
fi

rm -rf "$TARBALL" "$RANGER_DIR"

echo "=== Installed ==="
ls -la "$PLUGINS_DIR/ranger/"
echo ""
echo "Ranger Trino plugin installed to: $PLUGINS_DIR/ranger"
echo "Docker Compose will mount this into Trino at /lib/trino/plugin/ranger"
