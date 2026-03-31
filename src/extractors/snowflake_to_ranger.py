"""Snowflake RBAC -> Ranger policy extractor.

Connects to Snowflake via snowflake-connector-python, reads RBAC grants,
masking policies, and row access policies for the FEDERATION_DEMO database,
and pushes normalised Ranger policies via the Ranger REST API.

Labels: source:snowflake, governance_tier:platform_native
"""

from __future__ import annotations

import logging
import os
from typing import Any

import snowflake.connector
from dotenv import load_dotenv

from src.extractors.base import BaseExtractor
from src.utils.sql_safety import validate_identifier

load_dotenv()

logger = logging.getLogger(__name__)

# Snowflake privilege -> Ranger access type mapping
SNOWFLAKE_PRIVILEGE_MAP: dict[str, str] = {
    "SELECT": "select",
    "INSERT": "insert",
    "UPDATE": "insert",
    "DELETE": "delete",
    "TRUNCATE": "drop",
    "REFERENCES": "select",
    "USAGE": "use",
    "OPERATE": "alter",
    "MONITOR": "select",
    "CREATE TABLE": "create",
    "CREATE VIEW": "create",
    "CREATE SCHEMA": "create",
    "OWNERSHIP": "all",
}


class SnowflakeExtractor(BaseExtractor):
    """Extract Snowflake RBAC grants, masking, and RLS and convert to Ranger."""

    def __init__(self) -> None:
        super().__init__(source_name="snowflake")
        self.account: str = os.getenv("SNOWFLAKE_ACCOUNT", "")
        self.user: str = os.getenv("SNOWFLAKE_USER", "")
        self.password: str = os.getenv("SNOWFLAKE_PASSWORD", "")
        self.warehouse: str = os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
        self.database: str = validate_identifier(
            os.getenv("SNOWFLAKE_DATABASE", "FEDERATION_DEMO")
        )
        self.role: str = os.getenv("SNOWFLAKE_ROLE", "")

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self) -> snowflake.connector.SnowflakeConnection:
        """Open a Snowflake connection."""
        logger.info(
            "Connecting to Snowflake account=%s database=%s role=%s",
            self.account,
            self.database,
            self.role,
        )
        return snowflake.connector.connect(
            account=self.account,
            user=self.user,
            password=self.password,
            warehouse=self.warehouse,
            database=self.database,
            role=self.role or None,
            login_timeout=30,
            network_timeout=30,
        )

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_policies(self) -> list[dict[str, Any]]:
        """Pull Snowflake grants and policies, normalise into Ranger format."""
        conn = self._connect()
        try:
            raw_grants = self._collect_all_grants(conn)
            logger.info(
                "Collected %d raw Snowflake grants for database '%s'",
                len(raw_grants),
                self.database,
            )
            return self._grants_to_ranger_policies(raw_grants)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Grant collection
    # ------------------------------------------------------------------

    def _collect_all_grants(
        self, conn: snowflake.connector.SnowflakeConnection
    ) -> list[dict[str, Any]]:
        """Collect database grants, schema grants, table grants, masking, and RLS."""
        grants: list[dict[str, Any]] = []

        # Database-level grants
        grants.extend(self._get_database_grants(conn))

        # Discover schemas
        schemas = self._discover_schemas(conn)

        for schema_name in schemas:
            # Schema-level grants
            grants.extend(self._get_schema_grants(conn, schema_name))

            # Discover tables within each schema
            tables = self._discover_tables(conn, schema_name)

            for table_name in tables:
                # Table-level grants
                grants.extend(
                    self._get_table_grants(conn, schema_name, table_name)
                )

            # Masking policies in this schema
            grants.extend(self._get_masking_policies(conn, schema_name))

            # Row access policies in this schema
            grants.extend(self._get_row_access_policies(conn, schema_name))

        return grants

    def _discover_schemas(
        self, conn: snowflake.connector.SnowflakeConnection
    ) -> list[str]:
        """Discover schemas in the database."""
        schemas: list[str] = []
        cur = conn.cursor()
        try:
            # Note: SHOW commands do not support parameterized identifiers;
            # self.database is validated via validate_identifier() in __init__
            cur.execute(f"SHOW SCHEMAS IN DATABASE {self.database}")
            for row in cur.fetchall():
                schema_name = row[1]  # name is second column
                # Skip internal schemas
                if schema_name not in ("INFORMATION_SCHEMA",):
                    schemas.append(schema_name)
            logger.info(
                "Discovered %d schemas in database '%s': %s",
                len(schemas),
                self.database,
                schemas,
            )
        except snowflake.connector.errors.ProgrammingError as exc:
            logger.warning("Could not list Snowflake schemas: %s", exc)
            schemas = ["PUBLIC"]
        finally:
            cur.close()
        return schemas

    def _discover_tables(
        self,
        conn: snowflake.connector.SnowflakeConnection,
        schema: str,
    ) -> list[str]:
        """Discover tables in a schema."""
        tables: list[str] = []
        cur = conn.cursor()
        try:
            validate_identifier(schema)
            cur.execute(
                f"SHOW TABLES IN SCHEMA {self.database}.{schema}"
            )
            for row in cur.fetchall():
                tables.append(row[1])  # name is second column
            logger.info(
                "Discovered %d tables in schema '%s.%s': %s",
                len(tables),
                self.database,
                schema,
                tables,
            )
        except snowflake.connector.errors.ProgrammingError as exc:
            logger.debug(
                "Could not list tables in schema '%s': %s", schema, exc
            )
        finally:
            cur.close()
        return tables

    def _get_database_grants(
        self, conn: snowflake.connector.SnowflakeConnection
    ) -> list[dict[str, Any]]:
        """Get grants on the database object."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            # Note: SHOW commands do not support parameterized identifiers;
            # self.database is validated via validate_identifier() in __init__
            cur.execute(f"SHOW GRANTS ON DATABASE {self.database}")
            for row in cur.fetchall():
                # SHOW GRANTS ON DATABASE columns:
                # created_on, privilege, granted_on, name, granted_to, grantee_name, grant_option, granted_by
                privilege = row[1]
                granted_to = row[4]
                grantee_name = row[5]
                grant_option = row[6]

                grants.append(
                    {
                        "principal": grantee_name,
                        "principal_type": granted_to.lower(),  # 'ROLE' -> 'role'
                        "privilege": privilege,
                        "grantable": grant_option == "true",
                        "database": self.database,
                        "schema": "*",
                        "table": "*",
                        "columns": ["*"],
                        "level": "database",
                        "source": "snowflake_rbac",
                    }
                )
        except snowflake.connector.errors.ProgrammingError as exc:
            logger.warning("Could not get database grants: %s", exc)
        finally:
            cur.close()
        return grants

    def _get_schema_grants(
        self,
        conn: snowflake.connector.SnowflakeConnection,
        schema: str,
    ) -> list[dict[str, Any]]:
        """Get grants on a schema."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            validate_identifier(schema)
            cur.execute(
                f"SHOW GRANTS ON SCHEMA {self.database}.{schema}"
            )
            for row in cur.fetchall():
                privilege = row[1]
                granted_to = row[4]
                grantee_name = row[5]

                grants.append(
                    {
                        "principal": grantee_name,
                        "principal_type": granted_to.lower(),
                        "privilege": privilege,
                        "grantable": False,
                        "database": self.database,
                        "schema": schema,
                        "table": "*",
                        "columns": ["*"],
                        "level": "schema",
                        "source": "snowflake_rbac",
                    }
                )
        except snowflake.connector.errors.ProgrammingError as exc:
            logger.debug(
                "Could not get schema grants for '%s': %s", schema, exc
            )
        finally:
            cur.close()
        return grants

    def _get_table_grants(
        self,
        conn: snowflake.connector.SnowflakeConnection,
        schema: str,
        table: str,
    ) -> list[dict[str, Any]]:
        """Get grants on a specific table."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            validate_identifier(schema)
            validate_identifier(table)
            cur.execute(
                f"SHOW GRANTS ON TABLE {self.database}.{schema}.{table}"
            )
            for row in cur.fetchall():
                privilege = row[1]
                granted_to = row[4]
                grantee_name = row[5]

                grants.append(
                    {
                        "principal": grantee_name,
                        "principal_type": granted_to.lower(),
                        "privilege": privilege,
                        "grantable": False,
                        "database": self.database,
                        "schema": schema,
                        "table": table,
                        "columns": ["*"],
                        "level": "table",
                        "source": "snowflake_rbac",
                    }
                )
        except snowflake.connector.errors.ProgrammingError as exc:
            logger.debug(
                "Could not get table grants for '%s.%s': %s",
                schema,
                table,
                exc,
            )
        finally:
            cur.close()
        return grants

    def _get_masking_policies(
        self,
        conn: snowflake.connector.SnowflakeConnection,
        schema: str,
    ) -> list[dict[str, Any]]:
        """Discover masking policies in a schema."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            validate_identifier(schema)
            cur.execute(
                f"SHOW MASKING POLICIES IN SCHEMA {self.database}.{schema}"
            )
            for row in cur.fetchall():
                # SHOW MASKING POLICIES columns:
                # created_on, name, database_name, schema_name, kind, owner
                policy_name = row[1]
                grants.append(
                    {
                        "principal": "__all__",
                        "principal_type": "all",
                        "privilege": "masking",
                        "grantable": False,
                        "database": self.database,
                        "schema": schema,
                        "table": "*",
                        "columns": ["*"],
                        "level": "schema",
                        "mask_policy_name": policy_name,
                        "source": "snowflake_masking",
                    }
                )
                logger.info(
                    "Found Snowflake masking policy '%s' in %s.%s",
                    policy_name,
                    self.database,
                    schema,
                )

            # If masking policies exist, try to get their assignments
            if grants:
                self._get_masking_policy_refs(conn, schema, grants)

        except snowflake.connector.errors.ProgrammingError as exc:
            logger.debug(
                "No masking policies in schema '%s': %s", schema, exc
            )
        finally:
            cur.close()
        return grants

    def _get_masking_policy_refs(
        self,
        conn: snowflake.connector.SnowflakeConnection,
        schema: str,
        grants: list[dict[str, Any]],
    ) -> None:
        """Try to resolve which columns have masking policies applied.

        Updates the grants in-place with column and table info from
        INFORMATION_SCHEMA.POLICY_REFERENCES if available.
        """
        cur = conn.cursor()
        try:
            cur.execute(
                f"SELECT policy_name, ref_entity_name, ref_column_name "
                f"FROM {self.database}.INFORMATION_SCHEMA.POLICY_REFERENCES "
                f"WHERE policy_kind = 'MASKING_POLICY' "
                f"  AND ref_schema_name = %s",
                (schema,),
            )
            ref_map: dict[str, list[tuple[str, str]]] = {}
            for row in cur.fetchall():
                policy_name = row[0]
                table_name = row[1]
                column_name = row[2]
                if policy_name not in ref_map:
                    ref_map[policy_name] = []
                ref_map[policy_name].append((table_name, column_name))

            # Enrich the grants with actual references
            for g in grants:
                mask_name = g.get("mask_policy_name", "")
                if mask_name in ref_map:
                    refs = ref_map[mask_name]
                    g["table"] = refs[0][0]
                    g["columns"] = [r[1] for r in refs]

        except snowflake.connector.errors.ProgrammingError as exc:
            logger.debug(
                "Could not query POLICY_REFERENCES for schema '%s': %s",
                schema,
                exc,
            )
        finally:
            cur.close()

    def _get_row_access_policies(
        self,
        conn: snowflake.connector.SnowflakeConnection,
        schema: str,
    ) -> list[dict[str, Any]]:
        """Discover row access policies in a schema."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            validate_identifier(schema)
            cur.execute(
                f"SHOW ROW ACCESS POLICIES IN SCHEMA {self.database}.{schema}"
            )
            for row in cur.fetchall():
                policy_name = row[1]
                grants.append(
                    {
                        "principal": "__all__",
                        "principal_type": "all",
                        "privilege": "row_filter",
                        "grantable": False,
                        "database": self.database,
                        "schema": schema,
                        "table": "*",
                        "columns": ["*"],
                        "level": "schema",
                        "rap_policy_name": policy_name,
                        "source": "snowflake_row_access",
                    }
                )
                logger.info(
                    "Found Snowflake row access policy '%s' in %s.%s",
                    policy_name,
                    self.database,
                    schema,
                )
        except snowflake.connector.errors.ProgrammingError as exc:
            logger.debug(
                "No row access policies in schema '%s': %s", schema, exc
            )
        finally:
            cur.close()
        return grants

    # ------------------------------------------------------------------
    # Ranger policy conversion
    # ------------------------------------------------------------------

    def _grants_to_ranger_policies(
        self, grants: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert Snowflake grants into Ranger policies."""
        access_grants: list[dict[str, Any]] = []
        masking_grants: list[dict[str, Any]] = []
        row_access_grants: list[dict[str, Any]] = []

        for g in grants:
            if g["source"] == "snowflake_masking":
                masking_grants.append(g)
            elif g["source"] == "snowflake_row_access":
                row_access_grants.append(g)
            else:
                access_grants.append(g)

        policies: list[dict[str, Any]] = []

        # --- Access policies (grouped by table + principal) ---
        grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for g in access_grants:
            key = (g["schema"], g["table"], g["principal"], g["level"])
            ranger_access = SNOWFLAKE_PRIVILEGE_MAP.get(
                g["privilege"].upper(), "select"
            )
            if key not in grouped:
                grouped[key] = {
                    "schema": g["schema"],
                    "table": g["table"],
                    "principal": g["principal"],
                    "principal_type": g.get("principal_type", "role"),
                    "level": g["level"],
                    "accesses": set(),
                    "original_grants": [],
                }
            grouped[key]["accesses"].add(ranger_access)
            grouped[key]["original_grants"].append(
                f"GRANT {g['privilege']} ON {g['level']} {g['schema']}.{g['table']} TO {g['principal']}"
            )

        for (schema, table, principal, level), agg in grouped.items():
            safe_principal = (
                principal.replace(" ", "_")
                .replace(":", "_")
                .replace("/", "_")
                .replace(".", "_")
                .lower()
            )
            policy_name = f"sf_{schema}_{table}_{safe_principal}_{level}"

            users: list[str] = []
            groups: list[str] = []
            if agg["principal_type"] == "role":
                groups.append(principal)
            else:
                users.append(principal)

            accesses = [
                {"type": a, "isAllowed": True} for a in sorted(agg["accesses"])
            ]

            extra_labels = [
                "governance_tier:platform_native",
                f"snowflake_schema:{schema}",
                f"snowflake_level:{level}",
                f"original_grant:{'; '.join(agg['original_grants'][:3])}",
            ]

            policy = self.make_access_policy(
                name=policy_name,
                database="snowflake",
                table=table,
                users=users,
                groups=groups,
                accesses=accesses,
                extra_labels=extra_labels,
                schema=schema.lower(),
            )
            policies.append(policy)

        # --- Masking policies ---
        for g in masking_grants:
            mask_name = g.get("mask_policy_name", "unknown")
            table = g.get("table", "*")
            columns = g.get("columns", ["*"])

            for col in columns:
                safe_name = (
                    f"sf_mask_{g['schema']}_{table}_{col}_{mask_name}"
                    .replace(" ", "_")
                    .lower()
                )

                extra_labels = [
                    "governance_tier:platform_native",
                    f"snowflake_mask_policy:{mask_name}",
                    f"snowflake_schema:{g['schema']}",
                ]

                policy = self.make_masking_policy(
                    name=safe_name,
                    database="snowflake",
                    table=table,
                    column=col,
                    mask_type="MASK_HASH",
                    groups=["public"],
                    extra_labels=extra_labels,
                    schema=g["schema"].lower(),
                )
                policies.append(policy)

        # --- Row access policies ---
        for g in row_access_grants:
            rap_name = g.get("rap_policy_name", "unknown")
            safe_name = (
                f"sf_rap_{g['schema']}_{g['table']}_{rap_name}"
                .replace(" ", "_")
                .lower()
            )

            extra_labels = [
                "governance_tier:platform_native",
                f"snowflake_rap_policy:{rap_name}",
                f"snowflake_schema:{g['schema']}",
            ]

            policy = self.make_row_filter_policy(
                name=safe_name,
                database="snowflake",
                table=g["table"],
                filter_expr=f"/* Snowflake RAP: {rap_name} */ true",
                groups=["public"],
                extra_labels=extra_labels,
                schema=g["schema"].lower(),
            )
            policies.append(policy)

        return policies


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = SnowflakeExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Snowflake extractor result: %s", result)
