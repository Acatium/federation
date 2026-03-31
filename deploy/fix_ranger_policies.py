#!/usr/bin/env python3
"""Add test_user to all default Ranger access policies for dev_trino.

This allows test_user to query through Trino with Ranger enforcing masking.
restricted_user is NOT added — they should remain denied at the table level.
"""
import json
import os
import subprocess
import sys

RANGER_URL = "http://localhost:6080"
SERVICE = "dev_trino"
AUTH = f"admin:{os.environ.get('RANGER_ADMIN_PASSWORD', 'changeme')}"

# Default policy IDs that grant wildcard access (only user 'trino' currently)
DEFAULT_POLICY_IDS = [24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35]


def curl_get(url: str) -> dict:
    result = subprocess.run(
        ["curl", "-s", "-u", AUTH, url],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)


def curl_put(url: str, data: dict) -> dict:
    result = subprocess.run(
        ["curl", "-s", "-X", "PUT", "-u", AUTH,
         "-H", "Content-Type: application/json",
         url, "-d", json.dumps(data)],
        capture_output=True, text=True
    )
    return json.loads(result.stdout)


def main():
    for pid in DEFAULT_POLICY_IDS:
        policy = curl_get(f"{RANGER_URL}/service/public/v2/api/policy/{pid}")
        name = policy.get("name", "?")
        changed = False

        for item in policy.get("policyItems", []):
            users = item.get("users", [])
            if "trino" in users and "test_user" not in users:
                users.append("test_user")
                item["users"] = users
                changed = True

        if changed:
            result = curl_put(
                f"{RANGER_URL}/service/public/v2/api/policy/{pid}",
                policy
            )
            result_users = result.get("policyItems", [{}])[0].get("users", [])
            print(f"Updated {pid}: {name} -> users: {result_users}")
        else:
            print(f"Skipped {pid}: {name} (test_user already present or no trino user)")


if __name__ == "__main__":
    main()
