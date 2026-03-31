"""Redshift RBAC -> Ranger policy extractor.

Connects to Redshift Serverless via psycopg2, queries system views for
table-level grants, column-level grants, and row-level security policies,
then pushes normalised Ranger policies via the Ranger REST API.

Labels: source:redshift, governance_tier:platform_native
"""

from __future__ import annotations

import logging
import os
from typing import Any

import psycopg2
from dotenv import load_dotenv

from src.extractors.base import BaseExtractor
from src.utils.sql_safety import validate_row_filter_expr

load_dotenv()

logger = logging.getLogger(__name__)

# Redshift privilege -> Ranger access type mapping
REDSHIFT_PRIVILEGE_MAP: dict[str, str] = {
    "SELECT": "select",
    "INSERT": "insert",
    "UPDATE": "insert",
    "DELETE": "delete",
    "REFERENCES": "select",
    "EXECUTE": "execute",
    "USAGE": "use",
    "CREATE": "create",
    "TEMPORARY": "select",
    "TEMP": "select",
}

# Schemas to inspect in Redshift
REDSHIFT_SCHEMAS: list[str] = ["public", "spectrum_federation"]


class RedshiftExtractor(BaseExtractor):
    """Extract Redshift RBAC grants + RLS policies and convert to Ranger format."""

    def __init__(self) -> None:
        super().__init__(source_name="redshift")
        self.host: str = os.getenv("REDSHIFT_HOST", "")
        self.port: int = int(os.getenv("REDSHIFT_PORT", "5439"))
        self.database: str = os.getenv("REDSHIFT_DATABASE", "dev")
        self.user: str = os.getenv("REDSHIFT_USER", "admin")
        self.password: str = os.getenv("REDSHIFT_PASSWORD", "")

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self) -> psycopg2.extensions.connection:
        """Open a psycopg2 connection to Redshift."""
        logger.info(
            "Connecting to Redshift at %s:%s database=%s user=%s",
            self.host,
            self.port,
            self.database,
            self.user,
        )
        return psycopg2.connect(
            host=self.host,
            port=self.port,
            dbname=self.database,
            user=self.user,
            password=self.password,
            sslmode="require",
            connect_timeout=30,
        )

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_policies(self) -> list[dict[str, Any]]:
        """Pull Redshift grants and RLS and normalise into Ranger policy dicts."""
        conn = self._connect()
        try:
            raw_grants = self._collect_all_grants(conn)
            logger.info(
                "Collected %d raw Redshift grants across schemas %s",
                len(raw_grants),
                REDSHIFT_SCHEMAS,
            )
            return self._grants_to_ranger_policies(raw_grants)
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Grant collection
    # ------------------------------------------------------------------

    def _collect_all_grants(
        self, conn: psycopg2.extensions.connection
    ) -> list[dict[str, Any]]:
        """Collect table grants, column grants, and RLS from Redshift."""
        grants: list[dict[str, Any]] = []

        # Discover external tables (Spectrum)
        external_tables: set[tuple[str, str]] = set()
        cur = conn.cursor()
        try:
            cur.execute("SELECT schemaname, tablename FROM svv_external_tables")
            for row in cur.fetchall():
                external_tables.add((row[0], row[1]))
        except psycopg2.Error as exc:
            logger.debug("Could not query svv_external_tables (may not have Spectrum): %s", exc)
            conn.rollback()
        finally:
            cur.close()

        for schema in REDSHIFT_SCHEMAS:
            tables = self._discover_tables(conn, schema)
            for table_name in tables:
                table_grants = self._get_table_privileges(conn, schema, table_name)

                # For external (Spectrum) tables, synthesize admin access if no
                # grants found — system views don't cover external tables.
                if not table_grants and (schema, table_name) in external_tables:
                    logger.info(
                        "Synthesizing admin grant for external table %s.%s",
                        schema, table_name,
                    )
                    table_grants.append({
                        "principal": self.user,
                        "principal_type": "user",
                        "privilege": "SELECT",
                        "grantable": True,
                        "schema": schema,
                        "table": table_name,
                        "columns": ["*"],
                        "source": "redshift_external_synthesized",
                    })

                grants.extend(table_grants)
                grants.extend(self._get_column_privileges(conn, schema, table_name))
                grants.extend(self._get_rls_policies(conn, schema, table_name))

        return grants

    def _discover_tables(
        self, conn: psycopg2.extensions.connection, schema: str
    ) -> list[str]:
        """List tables in the given schema."""
        tables: list[str] = []
        cur = conn.cursor()
        try:
            # Use information_schema which works for both internal and external tables
            cur.execute(
                """
                SELECT DISTINCT tablename
                FROM pg_tables
                WHERE schemaname = %s
                UNION
                SELECT DISTINCT tablename
                FROM svv_external_tables
                WHERE schemaname = %s
                """,
                (schema, schema),
            )
            tables = [row[0] for row in cur.fetchall()]
            logger.info(
                "Discovered %d tables in Redshift schema '%s': %s",
                len(tables),
                schema,
                tables,
            )
        except psycopg2.Error as exc:
            logger.warning(
                "Could not list tables in schema '%s': %s", schema, exc
            )
            conn.rollback()
            # Fall back to known demo tables for the public schema
            if schema == "public":
                tables = ["ledger_entries"]
            elif schema == "spectrum_federation":
                tables = ["ledger_entries", "counterparty_ref"]
        finally:
            cur.close()

        return tables

    def _get_table_privileges(
        self,
        conn: psycopg2.extensions.connection,
        schema: str,
        table: str,
    ) -> list[dict[str, Any]]:
        """Query svv_relation_privileges for table-level grants."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT identity_name, identity_type, privilege_type, admin_option
                FROM svv_relation_privileges
                WHERE namespace_name = %s AND relation_name = %s
                """,
                (schema, table),
            )
            for row in cur.fetchall():
                grants.append(
                    {
                        "principal": row[0],
                        "principal_type": row[1],
                        "privilege": row[2],
                        "grantable": row[3],
                        "schema": schema,
                        "table": table,
                        "columns": ["*"],
                        "source": "redshift_rbac",
                    }
                )
        except psycopg2.Error as exc:
            logger.warning(
                "Could not query svv_relation_privileges for %s.%s: %s",
                schema,
                table,
                exc,
            )
            conn.rollback()
            # Fallback: check via HAS_TABLE_PRIVILEGE for the current user
            grants.extend(
                self._fallback_has_table_privilege(conn, schema, table)
            )
        finally:
            cur.close()

        # If no grants found via system views, fall back to HAS_TABLE_PRIVILEGE
        if not grants:
            grants.extend(
                self._fallback_has_table_privilege(conn, schema, table)
            )

        return grants

    def _fallback_has_table_privilege(
        self,
        conn: psycopg2.extensions.connection,
        schema: str,
        table: str,
    ) -> list[dict[str, Any]]:
        """Fallback: use HAS_TABLE_PRIVILEGE to detect current user's access."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            for priv in ["SELECT", "INSERT", "UPDATE", "DELETE"]:
                cur.execute(
                    "SELECT HAS_TABLE_PRIVILEGE(CURRENT_USER, %s, %s)",
                    (f"{schema}.{table}", priv),
                )
                result = cur.fetchone()
                if result and result[0]:
                    grants.append(
                        {
                            "principal": self.user,
                            "principal_type": "user",
                            "privilege": priv,
                            "grantable": False,
                            "schema": schema,
                            "table": table,
                            "columns": ["*"],
                            "source": "redshift_rbac_fallback",
                        }
                    )
        except psycopg2.Error as exc:
            logger.warning(
                "Fallback HAS_TABLE_PRIVILEGE failed for %s.%s: %s",
                schema,
                table,
                exc,
            )
            conn.rollback()
        finally:
            cur.close()

        return grants

    def _get_column_privileges(
        self,
        conn: psycopg2.extensions.connection,
        schema: str,
        table: str,
    ) -> list[dict[str, Any]]:
        """Query svv_column_privileges for column-level grants."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT grantee, column_name, privilege_type
                FROM svv_column_privileges
                WHERE table_schema = %s AND table_name = %s
                """,
                (schema, table),
            )
            for row in cur.fetchall():
                grants.append(
                    {
                        "principal": row[0],
                        "principal_type": "user",
                        "privilege": row[2],
                        "grantable": False,
                        "schema": schema,
                        "table": table,
                        "columns": [row[1]],
                        "source": "redshift_column_rbac",
                    }
                )
        except psycopg2.Error as exc:
            logger.debug(
                "No column-level privileges for %s.%s (may not exist): %s",
                schema,
                table,
                exc,
            )
            conn.rollback()
        finally:
            cur.close()

        return grants

    def _get_rls_policies(
        self,
        conn: psycopg2.extensions.connection,
        schema: str,
        table: str,
    ) -> list[dict[str, Any]]:
        """Query svv_rls_policy for row-level security policies."""
        grants: list[dict[str, Any]] = []
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT polname, polcmd, polroles, polqual
                FROM svv_rls_policy
                WHERE schema_name = %s AND table_name = %s
                """,
                (schema, table),
            )
            for row in cur.fetchall():
                pol_name = row[0]
                pol_roles = row[2] if row[2] else ""
                pol_qual = row[3] if row[3] else ""
                grants.append(
                    {
                        "principal": pol_roles,
                        "principal_type": "role",
                        "privilege": "row_filter",
                        "grantable": False,
                        "schema": schema,
                        "table": table,
                        "columns": ["*"],
                        "filter_expr": pol_qual,
                        "rls_policy_name": pol_name,
                        "source": "redshift_rls",
                    }
                )
        except psycopg2.Error as exc:
            logger.debug(
                "No RLS policies for %s.%s (may not exist): %s",
                schema,
                table,
                exc,
            )
            conn.rollback()
        finally:
            cur.close()

        return grants

    # ------------------------------------------------------------------
    # Ranger policy conversion
    # ------------------------------------------------------------------

    def _grants_to_ranger_policies(
        self, grants: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert raw Redshift grants into Ranger policies.

        Groups by (schema, table, principal) for access policies.
        RLS policies get their own row-filter Ranger policy each.
        """
        # Separate access grants from RLS
        access_grants: list[dict[str, Any]] = []
        rls_grants: list[dict[str, Any]] = []
        for g in grants:
            if g["source"] == "redshift_rls":
                rls_grants.append(g)
            else:
                access_grants.append(g)

        policies: list[dict[str, Any]] = []

        # --- Access policies (grouped) ---
        grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
        for g in access_grants:
            key = (g["schema"], g["table"], g["principal"])
            ranger_access = REDSHIFT_PRIVILEGE_MAP.get(
                g["privilege"].upper(), "select"
            )
            if key not in grouped:
                grouped[key] = {
                    "schema": g["schema"],
                    "table": g["table"],
                    "principal": g["principal"],
                    "principal_type": g.get("principal_type", "user"),
                    "accesses": set(),
                    "columns": set(),
                    "original_grants": [],
                }
            grouped[key]["accesses"].add(ranger_access)
            for col in g.get("columns", ["*"]):
                grouped[key]["columns"].add(col)
            grouped[key]["original_grants"].append(
                f"GRANT {g['privilege']} ON {g['schema']}.{g['table']} TO {g['principal']}"
            )

        for (schema, table, principal), agg in grouped.items():
            safe_principal = (
                principal.replace(" ", "_")
                .replace(":", "_")
                .replace("/", "_")
                .lower()
            )
            policy_name = f"rs_{schema}_{table}_{safe_principal}"

            users: list[str] = []
            groups: list[str] = []
            if agg["principal_type"] in ("role", "group"):
                groups.append(principal)
            else:
                users.append(principal)

            accesses = [
                {"type": a, "isAllowed": True} for a in sorted(agg["accesses"])
            ]
            columns = (
                sorted(agg["columns"]) if "*" not in agg["columns"] else ["*"]
            )

            extra_labels = [
                "governance_tier:platform_native",
                f"redshift_schema:{schema}",
                f"original_grant:{'; '.join(agg['original_grants'][:3])}",
            ]

            policy = self.make_access_policy(
                name=policy_name,
                database="redshift",
                table=table,
                columns=columns,
                users=users,
                groups=groups,
                accesses=accesses,
                extra_labels=extra_labels,
                schema=schema,
            )
            policies.append(policy)

        # --- RLS row-filter policies ---
        for g in rls_grants:
            rls_name = g.get("rls_policy_name", "unnamed")
            filter_expr = g.get("filter_expr", "true")
            try:
                validate_row_filter_expr(filter_expr)
            except ValueError as exc:
                logger.warning(
                    "Skipping unsafe RLS filter for %s.%s: %s",
                    g["schema"], g["table"], exc,
                )
                continue
            safe_name = (
                f"rs_rls_{g['schema']}_{g['table']}_{rls_name}"
                .replace(" ", "_")
                .lower()
            )

            extra_labels = [
                "governance_tier:platform_native",
                f"redshift_schema:{g['schema']}",
                f"rls_policy:{rls_name}",
                f"original_filter:{filter_expr[:200]}",
            ]

            # For RLS, the principal field may contain multiple roles
            roles = [
                r.strip()
                for r in g["principal"].split(",")
                if r.strip()
            ]
            groups = roles if roles else ["public"]

            policy = self.make_row_filter_policy(
                name=safe_name,
                database="redshift",
                table=g["table"],
                filter_expr=filter_expr,
                groups=groups,
                extra_labels=extra_labels,
                schema=g["schema"],
            )
            policies.append(policy)

        return policies


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = RedshiftExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Redshift extractor result: %s", result)
