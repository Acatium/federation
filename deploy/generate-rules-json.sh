#!/usr/bin/env bash
# Generate Trino file-based access control rules from Ranger policies.
#
# Fallback for when the Ranger Trino plugin cannot load. This script queries
# the Ranger REST API for all dev_trino policies and converts them into
# Trino's rules.json format for file-based access control.
#
# Usage:
#   bash deploy/generate-rules-json.sh
#
# Requires: RANGER_HOST, RANGER_PORT, RANGER_ADMIN_PASSWORD in .env

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load environment
set -a
source "$PROJECT_ROOT/.env"
set +a

RANGER_URL="http://${RANGER_HOST}:${RANGER_PORT}"
OUTPUT_FILE="$SCRIPT_DIR/trino-config/rules.json"

echo "=== Generating Trino rules.json from Ranger policies ==="
echo "  Ranger: $RANGER_URL"
echo "  Output: $OUTPUT_FILE"

python3 -c "
import json
import sys
import requests

RANGER_URL = '${RANGER_URL}'
RANGER_AUTH = ('${RANGER_ADMIN_USER:-admin}', '${RANGER_ADMIN_PASSWORD}')
SERVICE = '${RANGER_SERVICE:-dev_trino}'

try:
    resp = requests.get(
        f'{RANGER_URL}/service/public/v2/api/policy',
        params={'serviceName': SERVICE},
        auth=RANGER_AUTH,
        timeout=30,
    )
    resp.raise_for_status()
    policies = resp.json()
except Exception as e:
    print(f'[ERROR] Cannot fetch Ranger policies: {e}', file=sys.stderr)
    sys.exit(1)

# Convert to Trino file-based rules format
catalogs = []
for p in policies:
    if p.get('policyType', 0) != 0:
        continue
    if not p.get('isEnabled', True):
        continue

    resources = p.get('resources', {})
    catalog_vals = resources.get('catalog', {}).get('values', ['*'])
    schema_vals = resources.get('schema', {}).get('values', ['*'])
    table_vals = resources.get('table', {}).get('values', ['*'])

    for item in p.get('policyItems', []):
        users = item.get('users', [])
        groups = item.get('groups', [])
        accesses = [a['type'] for a in item.get('accesses', []) if a.get('isAllowed')]

        privileges = []
        for a in accesses:
            if a == 'select':
                privileges.append('SELECT')
            elif a == 'insert':
                privileges.append('INSERT')
            elif a == 'create':
                privileges.append('CREATE_TABLE')
            elif a == 'drop':
                privileges.append('DROP_TABLE')
            elif a == 'alter':
                privileges.append('ALTER_TABLE')
            elif a == 'all':
                privileges.extend(['SELECT', 'INSERT', 'CREATE_TABLE', 'DROP_TABLE', 'ALTER_TABLE'])

        if not privileges:
            continue

        for user in users:
            catalogs.append({
                'user': user,
                'catalog': '|'.join(catalog_vals),
                'schema': '|'.join(schema_vals),
                'table': '|'.join(table_vals),
                'privileges': privileges,
            })
        for group in groups:
            catalogs.append({
                'group': group,
                'catalog': '|'.join(catalog_vals),
                'schema': '|'.join(schema_vals),
                'table': '|'.join(table_vals),
                'privileges': privileges,
            })

# Build rules.json
rules = {
    'catalogs': [
        {'allow': 'all'}
    ],
    'tables': catalogs if catalogs else [
        {'user': 'test_user', 'privileges': ['SELECT']},
    ],
}

with open('${OUTPUT_FILE}', 'w') as f:
    json.dump(rules, f, indent=2)

print(f'[OK] Generated {len(catalogs)} table rules from {len(policies)} Ranger policies')
print(f'     Output: ${OUTPUT_FILE}')
print()
print('To use file-based access control instead of the Ranger plugin:')
print('  1. Edit deploy/trino-config/access-control.properties:')
print('     access-control.name=file')
print('     security.config-file=/etc/trino/rules.json')
print('  2. Add to docker-compose.yml Trino volumes:')
print('     - ./trino-config/rules.json:/etc/trino/rules.json')
"
