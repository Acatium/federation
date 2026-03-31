"""Lake Formation -> Ranger policy extractor.

Connects to AWS Lake Formation via boto3, reads permissions on the Glue
database ``federation_demo`` and its tables, and pushes normalised Ranger
policies via the Ranger REST API.

Labels: source:lake_formation, governance_tier:platform_native
"""

from __future__ import annotations

import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from src.extractors.base import (
    BaseExtractor,
    DEMO_DATABASE,
    DEMO_TABLES,
)

load_dotenv()

logger = logging.getLogger(__name__)

# Lake Formation permission -> Ranger access type mapping
LF_PERMISSION_MAP: dict[str, str] = {
    "ALL": "all",
    "SELECT": "select",
    "INSERT": "insert",
    "DELETE": "delete",
    "DESCRIBE": "select",
    "ALTER": "alter",
    "DROP": "drop",
    "CREATE_TABLE": "create",
    "CREATE_DATABASE": "create",
    "DATA_LOCATION_ACCESS": "select",
}


class LakeFormationExtractor(BaseExtractor):
    """Extract Lake Formation grants and convert to Ranger policies."""

    def __init__(self) -> None:
        super().__init__(source_name="lake_formation")
        self.region: str = os.getenv("AWS_REGION", "us-east-2")
        self.catalog_id: str = os.getenv(
            "GLUE_CATALOG_ID", os.getenv("AWS_ACCOUNT_ID", "")
        )
        self.database: str = os.getenv("GLUE_DATABASE", DEMO_DATABASE)
        self.lf_client = boto3.client("lakeformation", region_name=self.region)
        self.glue_client = boto3.client("glue", region_name=self.region)

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_policies(self) -> list[dict[str, Any]]:
        """Pull LF permissions and normalise into Ranger policy dicts."""
        raw_grants = self._collect_all_grants()
        logger.info(
            "Collected %d raw Lake Formation grants for database '%s'",
            len(raw_grants),
            self.database,
        )
        return self._grants_to_ranger_policies(raw_grants)

    # ------------------------------------------------------------------
    # Grant collection
    # ------------------------------------------------------------------

    def _collect_all_grants(self) -> list[dict[str, Any]]:
        """Collect database-level and table-level LF grants."""
        grants: list[dict[str, Any]] = []

        # Database-level permissions
        grants.extend(self._list_database_permissions())

        # Discover tables from Glue catalog
        tables = self._discover_tables()

        # Table-level permissions
        for table_name in tables:
            grants.extend(self._list_table_permissions(table_name))
            grants.extend(self._list_column_permissions(table_name))

        return grants

    def _discover_tables(self) -> list[str]:
        """Get table names from the Glue catalog for our database."""
        tables: list[str] = []
        try:
            paginator = self.glue_client.get_paginator("get_tables")
            for page in paginator.paginate(
                CatalogId=self.catalog_id, DatabaseName=self.database
            ):
                for tbl in page.get("TableList", []):
                    tables.append(tbl["Name"])
            logger.info(
                "Discovered %d tables in Glue database '%s': %s",
                len(tables),
                self.database,
                tables,
            )
        except ClientError as exc:
            logger.warning("Could not list Glue tables: %s", exc)
            # Fall back to known demo tables
            tables = list(DEMO_TABLES)
            logger.info("Using fallback table list: %s", tables)
        return tables

    def _list_database_permissions(self) -> list[dict[str, Any]]:
        """List LF permissions on the database resource."""
        grants: list[dict[str, Any]] = []
        try:
            kwargs: dict[str, Any] = {
                "Resource": {
                    "Database": {
                        "CatalogId": self.catalog_id,
                        "Name": self.database,
                    }
                }
            }
            while True:
                resp = self.lf_client.list_permissions(**kwargs)
                for perm in resp.get("PrincipalResourcePermissions", []):
                    grants.extend(self._parse_permission(perm, level="database"))
                next_token = resp.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except ClientError as exc:
            logger.warning(
                "Could not list database-level LF permissions: %s", exc
            )
        return grants

    def _list_table_permissions(self, table_name: str) -> list[dict[str, Any]]:
        """List LF permissions on a specific table."""
        grants: list[dict[str, Any]] = []
        try:
            kwargs: dict[str, Any] = {
                "Resource": {
                    "Table": {
                        "CatalogId": self.catalog_id,
                        "DatabaseName": self.database,
                        "Name": table_name,
                    }
                }
            }
            while True:
                resp = self.lf_client.list_permissions(**kwargs)
                for perm in resp.get("PrincipalResourcePermissions", []):
                    grants.extend(
                        self._parse_permission(
                            perm, level="table", table_name=table_name
                        )
                    )
                next_token = resp.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except ClientError as exc:
            logger.warning(
                "Could not list table-level LF permissions for '%s': %s",
                table_name,
                exc,
            )
        return grants

    def _list_column_permissions(self, table_name: str) -> list[dict[str, Any]]:
        """List LF column-level permissions (TableWithColumns resource)."""
        grants: list[dict[str, Any]] = []
        try:
            kwargs: dict[str, Any] = {
                "Resource": {
                    "TableWithColumns": {
                        "CatalogId": self.catalog_id,
                        "DatabaseName": self.database,
                        "Name": table_name,
                        "ColumnWildcard": {},
                    }
                }
            }
            while True:
                resp = self.lf_client.list_permissions(**kwargs)
                for perm in resp.get("PrincipalResourcePermissions", []):
                    grants.extend(
                        self._parse_permission(
                            perm, level="column", table_name=table_name
                        )
                    )
                next_token = resp.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except ClientError as exc:
            # Column-level permissions may not exist for every table
            logger.debug(
                "No column-level LF permissions for '%s': %s", table_name, exc
            )
        return grants

    # ------------------------------------------------------------------
    # Permission parsing
    # ------------------------------------------------------------------

    def _parse_permission(
        self,
        perm: dict[str, Any],
        level: str,
        table_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Parse a single LF PrincipalResourcePermission into normalised grants."""
        principal_id: str = perm["Principal"]["DataLakePrincipalIdentifier"]
        permissions: list[str] = perm.get("Permissions", [])
        grants_with_grant: list[str] = perm.get("PermissionsWithGrantOption", [])

        # Determine columns if column-level
        columns: list[str] = []
        if level == "column":
            twc = perm.get("Resource", {}).get("TableWithColumns", {})
            columns = twc.get("ColumnNames", [])

        grants: list[dict[str, Any]] = []
        for action in permissions:
            grant: dict[str, Any] = {
                "principal": principal_id,
                "privilege": action,
                "grantable": action in grants_with_grant,
                "database": self.database,
                "table": table_name or "*",
                "columns": columns if columns else ["*"],
                "level": level,
                "source": "lake_formation",
            }
            grants.append(grant)
        return grants

    # ------------------------------------------------------------------
    # Ranger policy conversion
    # ------------------------------------------------------------------

    def _grants_to_ranger_policies(
        self, grants: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert raw LF grants into de-duplicated Ranger policies.

        Groups grants by (table, columns) to produce one Ranger policy per
        unique resource scope, with multiple policyItems for different principals.
        """
        # Step 1: Group by (table, principal) to get per-principal access sets
        principal_grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for g in grants:
            key = (g["table"], g["principal"])
            ranger_access = LF_PERMISSION_MAP.get(g["privilege"], "select")
            if key not in principal_grouped:
                principal_grouped[key] = {
                    "table": g["table"],
                    "principal": g["principal"],
                    "database": g["database"],
                    "accesses": set(),
                    "columns": set(),
                    "original_grants": [],
                }
            principal_grouped[key]["accesses"].add(ranger_access)
            for col in g["columns"]:
                principal_grouped[key]["columns"].add(col)
            principal_grouped[key]["original_grants"].append(
                f"GRANT {g['privilege']} ON {g['table']} TO {g['principal']}"
            )

        # Step 2: Group by resource (table, frozen columns) to merge principals
        resource_grouped: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
        for (_table, _principal), agg in principal_grouped.items():
            columns = tuple(sorted(agg["columns"])) if "*" not in agg["columns"] else ("*",)
            resource_key = (agg["table"], columns)

            if resource_key not in resource_grouped:
                resource_grouped[resource_key] = {
                    "table": agg["table"],
                    "database": agg["database"],
                    "columns": list(columns),
                    "policy_items": [],
                    "original_grants": [],
                }

            principal = agg["principal"]
            is_role = "arn:" in principal and ":role/" in principal
            is_iam_user = "arn:" in principal and ":user/" in principal
            short_name = principal.split("/")[-1] if "arn:" in principal else principal

            users: list[str] = []
            groups: list[str] = []
            if is_role:
                groups.append(short_name)
            elif is_iam_user:
                users.append(short_name)
            else:
                users.append(short_name)

            accesses = [
                {"type": a, "isAllowed": True} for a in sorted(agg["accesses"])
            ]
            resource_grouped[resource_key]["policy_items"].append({
                "users": users,
                "groups": groups,
                "accesses": accesses,
            })
            resource_grouped[resource_key]["original_grants"].extend(
                agg["original_grants"][:3]
            )

        # Step 3: Build Ranger policies
        policies: list[dict[str, Any]] = []
        for (table, columns), rg in resource_grouped.items():
            col_tag = "cols" if columns != ("*",) else "all"
            policy_name = f"lf_{self.database}_{table}_{col_tag}"

            extra_labels = [
                "governance_tier:platform_native",
                f"original_grant:{'; '.join(rg['original_grants'][:5])}",
            ]

            policy = self.make_access_policy(
                name=policy_name,
                database="hive",
                table=table,
                columns=rg["columns"],
                extra_labels=extra_labels,
                schema=self.database,
            )
            # Replace the single policyItem with all merged items
            policy["policyItems"] = rg["policy_items"]
            policies.append(policy)

        return policies


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = LakeFormationExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Lake Formation extractor result: %s", result)
