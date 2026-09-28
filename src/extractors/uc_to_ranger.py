"""Unity Catalog -> Ranger policy extractor.

Connects to Databricks via the REST API, reads Unity Catalog permissions on
the configured catalog, schemas, and tables, and pushes normalised Ranger
policies via the Ranger REST API.

Labels: source:unity_catalog, governance_tier:platform_native
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import requests as http_requests
from dotenv import load_dotenv

from src.extractors.base import BaseExtractor

load_dotenv()

logger = logging.getLogger(__name__)

# Unity Catalog privilege -> Ranger access type mapping. Only privileges listed
# here become Ranger access; anything else (BROWSE, MANAGE, APPLY_TAG,
# EXTERNAL_USE_SCHEMA, ...) is skipped rather than guessed, so the mirror never
# grants more than the source does.
UC_PRIVILEGE_MAP: dict[str, str] = {
    "USE_CATALOG": "use",
    "USE_SCHEMA": "use",
    "SELECT": "select",
    "MODIFY": "insert",
    "CREATE_TABLE": "create",
    "CREATE_SCHEMA": "create",
    "CREATE_CATALOG": "create",
    "READ_FILES": "select",
    "WRITE_FILES": "insert",
    "EXECUTE": "execute",
    "ALL_PRIVILEGES": "all",
    "OWN": "all",
    "CREATE_FUNCTION": "create",
    "CREATE_MATERIALIZED_VIEW": "create",
    "CREATE_MODEL": "create",
    "CREATE_VOLUME": "create",
    "READ_VOLUME": "select",
    "WRITE_VOLUME": "insert",
}


# Service principals appear in grants by application ID.
_APPLICATION_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# Unity Catalog list endpoints return at most this many items per page.
_PAGE_SIZE = 1000


class ExtractionIncompleteError(RuntimeError):
    """Unity Catalog could not be read in full; pushing a partial mirror is refused."""


def _is_user(principal: str) -> bool:
    """Users are emails and service principals are application IDs; the rest are groups."""
    return "@" in principal or bool(_APPLICATION_ID.match(principal))


class UnityCatalogExtractor(BaseExtractor):
    """Extract Unity Catalog permissions and convert to Ranger policies."""

    def __init__(self) -> None:
        super().__init__(source_name="unity_catalog")
        self.host: str = os.getenv("DATABRICKS_HOST", "").rstrip("/")
        if self.host and not self.host.startswith("https://"):
            raise ValueError(
                f"DATABRICKS_HOST must use https:// (got {self.host!r}). "
                "Databricks API calls must be encrypted in transit."
            )
        self.token: str = os.getenv("DATABRICKS_TOKEN", "")
        self.catalog: str = os.getenv("DATABRICKS_CATALOG", "")
        self._session = http_requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # REST helpers
    # ------------------------------------------------------------------

    def _api_get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Make an authenticated GET to the Databricks REST API."""
        url = f"{self.host}/api/2.1/unity-catalog{path}"
        resp = self._session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _api_list(self, path: str, key: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """GET every page of a Unity Catalog list endpoint."""
        items: list[dict[str, Any]] = []
        page: dict[str, Any] = {**params, "max_results": _PAGE_SIZE}
        while True:
            data = self._api_get(path, params=page)
            items.extend(data.get(key, []))
            token = data.get("next_page_token")
            if not token:
                return items
            page = {**page, "page_token": token}

    def _permissions(self, securable: str, full_name: str) -> dict[str, Any]:
        """Read one securable's grants, or refuse to continue with a partial picture."""
        try:
            return self._api_get(f"/permissions/{securable}/{full_name}")
        except http_requests.RequestException as exc:
            raise ExtractionIncompleteError(
                f"could not read {securable} permissions for {full_name!r}: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_policies(self) -> list[dict[str, Any]]:
        """Pull UC permissions and normalise into Ranger policy dicts."""
        raw_grants = self._collect_all_grants()
        logger.info(
            "Collected %d raw Unity Catalog grants for catalog '%s'",
            len(raw_grants),
            self.catalog,
        )
        return self._grants_to_ranger_policies(raw_grants)

    # ------------------------------------------------------------------
    # Grant collection
    # ------------------------------------------------------------------

    def _collect_all_grants(self) -> list[dict[str, Any]]:
        """Collect catalog-level, schema-level, and table-level UC grants."""
        grants: list[dict[str, Any]] = []

        # Catalog-level permissions
        grants.extend(self._get_catalog_permissions())

        # Discover schemas
        schemas = self._discover_schemas()

        for schema_name in schemas:
            # Schema-level permissions
            grants.extend(self._get_schema_permissions(schema_name))

            # Discover tables in schema
            tables = self._discover_tables(schema_name)

            for table_name in tables:
                grants.extend(
                    self._get_table_permissions(schema_name, table_name)
                )

        return grants

    def _discover_schemas(self) -> list[str]:
        """List schemas in the catalog."""
        try:
            listed = self._api_list(
                "/schemas", "schemas", {"catalog_name": self.catalog}
            )
        except http_requests.RequestException as exc:
            raise ExtractionIncompleteError(
                f"could not list schemas in catalog {self.catalog!r}: {exc}"
            ) from exc
        # information_schema is system-generated and carries no grants.
        schemas = [
            s.get("name", "") for s in listed if s.get("name") != "information_schema"
        ]
        logger.info(
            "Discovered %d schemas in catalog '%s': %s",
            len(schemas),
            self.catalog,
            schemas,
        )
        return schemas

    def _discover_tables(self, schema: str) -> list[str]:
        """List tables in a schema."""
        try:
            listed = self._api_list(
                "/tables",
                "tables",
                {"catalog_name": self.catalog, "schema_name": schema},
            )
        except http_requests.RequestException as exc:
            raise ExtractionIncompleteError(
                f"could not list tables in {self.catalog}.{schema}: {exc}"
            ) from exc
        tables = [t.get("name", "") for t in listed]
        logger.info(
            "Discovered %d tables in '%s.%s': %s",
            len(tables),
            self.catalog,
            schema,
            tables,
        )
        return tables

    def _get_catalog_permissions(self) -> list[dict[str, Any]]:
        """Get permissions on the catalog; they apply to every schema and table in it."""
        return self._grants("catalog", self.catalog, schema="*", table="*")

    def _get_schema_permissions(self, schema: str) -> list[dict[str, Any]]:
        """Get permissions on a schema; they apply to every table in it."""
        return self._grants("schema", f"{self.catalog}.{schema}", schema=schema, table="*")

    def _get_table_permissions(
        self, schema: str, table: str
    ) -> list[dict[str, Any]]:
        """Get permissions on a table."""
        return self._grants(
            "table", f"{self.catalog}.{schema}.{table}", schema=schema, table=table
        )

    def _grants(
        self, level: str, full_name: str, *, schema: str, table: str
    ) -> list[dict[str, Any]]:
        grants: list[dict[str, Any]] = []
        data = self._permissions(level, full_name)
        for assignment in data.get("privilege_assignments", []):
            principal = assignment.get("principal", "")
            for priv in assignment.get("privileges", []):
                # Handle both string and dict privilege formats
                if isinstance(priv, dict):
                    privilege = priv.get("privilege", "")
                    inherited = priv.get("inherited_from_type")
                else:
                    privilege = str(priv)
                    inherited = None
                grants.append(
                    {
                        "principal": principal,
                        "privilege": privilege,
                        "catalog": self.catalog,
                        "schema": schema,
                        "table": table,
                        "columns": ["*"],
                        "level": level,
                        "inherited": inherited,
                        "source": "unity_catalog",
                    }
                )
        return grants

    # ------------------------------------------------------------------
    # Ranger policy conversion
    # ------------------------------------------------------------------

    def _grants_to_ranger_policies(
        self, grants: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert UC grants into Ranger policies.

        Groups by (schema, table, principal) to reduce policy count.
        """
        grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}

        for g in grants:
            key = (g["schema"], g["table"], g["principal"], g["level"])
            ranger_access = UC_PRIVILEGE_MAP.get(g["privilege"])
            if ranger_access is None:
                logger.info(
                    "Skipping UC privilege %s on %s.%s for %s: no Ranger data access",
                    g["privilege"], g["schema"], g["table"], g["principal"],
                )
                continue

            if key not in grouped:
                grouped[key] = {
                    "schema": g["schema"],
                    "table": g["table"],
                    "principal": g["principal"],
                    "catalog": g["catalog"],
                    "level": g["level"],
                    "accesses": set(),
                    "original_grants": [],
                }
            grouped[key]["accesses"].add(ranger_access)
            grouped[key]["original_grants"].append(
                f"GRANT {g['privilege']} ON {g['level']} {g['catalog']}.{g['schema']}.{g['table']} TO {g['principal']}"
            )

        policies: list[dict[str, Any]] = []
        for (schema, table, principal, level), agg in grouped.items():
            safe_principal = (
                principal.replace(" ", "_")
                .replace(":", "_")
                .replace("/", "_")
                .replace(".", "_")
                .replace("@", "_at_")
                .lower()
            )
            safe_schema = schema.replace(".", "_").replace("*", "all").lower()
            safe_table = table.replace(".", "_").replace("*", "all").lower()
            policy_name = (
                f"uc_{safe_schema}_{safe_table}_{safe_principal}_{level}"
            )

            users: list[str] = []
            groups: list[str] = []
            if _is_user(principal):
                users.append(principal)
            else:
                groups.append(principal)

            accesses = [
                {"type": a, "isAllowed": True} for a in sorted(agg["accesses"])
            ]

            extra_labels = [
                "governance_tier:platform_native",
                f"uc_catalog:{self.catalog}",
                f"uc_schema:{schema}",
                f"uc_level:{level}",
                f"original_grant:{'; '.join(agg['original_grants'][:3])}",
            ]

            policy = self.make_access_policy(
                name=policy_name,
                database="databricks",
                table=table,
                users=users,
                groups=groups,
                accesses=accesses,
                extra_labels=extra_labels,
                schema=schema,
            )
            policies.append(policy)

        return policies


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = UnityCatalogExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Unity Catalog extractor result: %s", result)
