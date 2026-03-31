"""Unified entitlement matrix — flat view of all Ranger policies.

Queries the Ranger REST API for all ``dev_trino`` policies and normalizes
them into a flat tabular format suitable for audit, comparison, and reporting.

Columns:
    dataset_name, platform, physical_location, principal, privilege,
    policy_type, source_system, extraction_timestamp

CLI:
    python -m src.reports.entitlement_matrix
"""

from __future__ import annotations

import logging
import os
from typing import Any

import polars as pl
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Expected output columns (used for empty-frame fallback)
MATRIX_COLUMNS: list[str] = [
    "dataset_name",
    "platform",
    "physical_location",
    "principal",
    "privilege",
    "policy_type",
    "source_system",
    "extraction_timestamp",
    "policy_name",
    "is_enabled",
]

POLICY_TYPE_NAMES: dict[int, str] = {
    0: "access",
    1: "masking",
    2: "row_filter",
}

# Catalog name -> inferred platform mapping
_CATALOG_PLATFORM_MAP: dict[str, str] = {
    "hive": "aws",
    "iceberg_s3": "aws",
    "redshift": "aws",
    "snowflake": "snowflake",
    "databricks": "databricks",
    "unity_catalog": "databricks",
}


def _empty_matrix() -> pl.DataFrame:
    """Return an empty DataFrame with the correct schema."""
    return pl.DataFrame({col: pl.Series([], dtype=pl.Utf8) for col in MATRIX_COLUMNS})


def _parse_source_from_labels(labels: list[str]) -> tuple[str, str]:
    """Extract source_system and extraction_timestamp from policyLabels.

    Args:
        labels: List of label strings (e.g., ["source:lake_formation", "extraction_ts:..."]).

    Returns:
        Tuple of (source_system, extraction_timestamp).
    """
    source = ""
    ts = ""
    for label in labels:
        if label.startswith("source:"):
            source = label[len("source:") :]
        elif label.startswith("extraction_ts:"):
            ts = label[len("extraction_ts:") :]
    return source, ts


def _infer_platform(catalog: str) -> str:
    """Infer the platform from a catalog name.

    Args:
        catalog: Trino catalog name.

    Returns:
        Platform string (e.g., "aws", "snowflake", "databricks").
    """
    return _CATALOG_PLATFORM_MAP.get(catalog, "unknown")


def _normalize_policy(policy: dict[str, Any]) -> list[dict[str, str]]:
    """Normalize a single Ranger policy into flat rows.

    Produces one row per (principal, privilege) combination in the policy.

    Args:
        policy: A Ranger policy dict.

    Returns:
        List of flat row dicts.
    """
    resources = policy.get("resources", {})
    catalog = ", ".join(resources.get("catalog", {}).get("values", ["*"]))
    schema = ", ".join(resources.get("schema", {}).get("values", ["*"]))
    table = ", ".join(resources.get("table", {}).get("values", ["*"]))
    column = ", ".join(resources.get("column", {}).get("values", []))

    dataset_name = f"{catalog}.{schema}.{table}"
    if column:
        dataset_name += f".{column}"

    platform = _infer_platform(catalog)
    physical_location = f"{platform}:{catalog}/{schema}/{table}"
    policy_type_int = policy.get("policyType", 0)
    policy_type = POLICY_TYPE_NAMES.get(policy_type_int, str(policy_type_int))
    policy_name = policy.get("name", "")
    is_enabled = str(policy.get("isEnabled", True))
    labels = policy.get("policyLabels", [])
    source_system, extraction_ts = _parse_source_from_labels(labels)

    rows: list[dict[str, str]] = []

    # Collect items from all policy item types
    items_keys = [
        ("policyItems", "access"),
        ("denyPolicyItems", "deny"),
        ("dataMaskPolicyItems", "masking"),
        ("rowFilterPolicyItems", "row_filter"),
    ]

    for items_key, _item_type in items_keys:
        for item in policy.get(items_key, []):
            principals: list[str] = []
            for u in item.get("users", []):
                principals.append(f"user:{u}")
            for g in item.get("groups", []):
                principals.append(f"group:{g}")

            privileges: list[str] = []
            for a in item.get("accesses", []):
                if a.get("isAllowed", True):
                    privileges.append(a.get("type", "select"))

            # For masking items, add mask type as privilege
            mask_info = item.get("dataMaskInfo", {})
            if mask_info:
                mask_type = mask_info.get("dataMaskType", "UNKNOWN")
                privileges.append(f"mask:{mask_type}")

            # For row filter items, add filter expression
            filter_info = item.get("rowFilterInfo", {})
            if filter_info:
                filter_expr = filter_info.get("filterExpr", "")
                privileges.append(f"filter:{filter_expr}")

            if not principals:
                principals = ["<none>"]
            if not privileges:
                privileges = ["<none>"]

            for principal in principals:
                for privilege in privileges:
                    rows.append(
                        {
                            "dataset_name": dataset_name,
                            "platform": platform,
                            "physical_location": physical_location,
                            "principal": principal,
                            "privilege": privilege,
                            "policy_type": policy_type,
                            "source_system": source_system,
                            "extraction_timestamp": extraction_ts,
                            "policy_name": policy_name,
                            "is_enabled": is_enabled,
                        }
                    )

    return rows


class EntitlementMatrix:
    """Unified entitlement matrix from Ranger policies.

    Queries the Ranger REST API for all dev_trino policies and normalizes
    them into a Polars DataFrame with one row per (principal, privilege).
    """

    def __init__(
        self,
        ranger_host: str | None = None,
        ranger_port: str | None = None,
        ranger_scheme: str | None = None,
        ranger_admin_user: str | None = None,
        ranger_admin_password: str | None = None,
        service_name: str | None = None,
    ) -> None:
        self.ranger_host = ranger_host or os.getenv("RANGER_HOST", "localhost")
        self.ranger_port = ranger_port or os.getenv("RANGER_PORT", "6080")
        self.ranger_scheme = ranger_scheme or os.getenv("RANGER_SCHEME", "http")
        self.auth = (
            ranger_admin_user or os.getenv("RANGER_ADMIN_USER", "admin"),
            ranger_admin_password or os.getenv("RANGER_ADMIN_PASSWORD", ""),
        )
        self.service_name = service_name or os.getenv("RANGER_SERVICE", "dev_trino")
        self.base_url = f"{self.ranger_scheme}://{self.ranger_host}:{self.ranger_port}"

    def fetch_policies(self) -> list[dict[str, Any]]:
        """Fetch all policies for the configured service from Ranger.

        Returns:
            List of Ranger policy dicts (empty list on connection failure).
        """
        url = f"{self.base_url}/service/public/v2/api/policy"
        try:
            resp = requests.get(
                url,
                params={"serviceName": self.service_name},
                auth=self.auth,
                timeout=30,
            )
            resp.raise_for_status()
            policies: list[dict[str, Any]] = resp.json()
            logger.info("Fetched %d policies from Ranger", len(policies))
            return policies
        except requests.RequestException as exc:
            logger.warning("Could not fetch Ranger policies: %s", exc)
            return []

    def build(self, policies: list[dict[str, Any]] | None = None) -> pl.DataFrame:
        """Build the entitlement matrix as a Polars DataFrame.

        Args:
            policies: Optional pre-fetched policies. If None, fetches from Ranger.

        Returns:
            Polars DataFrame with one row per (principal, privilege).
        """
        if policies is None:
            policies = self.fetch_policies()

        if not policies:
            return _empty_matrix()

        all_rows: list[dict[str, str]] = []
        for policy in policies:
            all_rows.extend(_normalize_policy(policy))

        if not all_rows:
            return _empty_matrix()

        return pl.DataFrame(all_rows)


def build_matrix(policies: list[dict[str, Any]] | None = None) -> pl.DataFrame:
    """Convenience function to build the entitlement matrix.

    Args:
        policies: Optional pre-fetched Ranger policies.

    Returns:
        Polars DataFrame.
    """
    matrix = EntitlementMatrix()
    return matrix.build(policies=policies)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    df = build_matrix()
    logger.info("Entitlement matrix: %d rows, %d columns", df.height, df.width)
    if df.height > 0:
        print(df)
    else:
        print("No policies found — ensure Ranger is running and policies are loaded.")
