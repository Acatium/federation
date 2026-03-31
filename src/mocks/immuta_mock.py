"""Immuta Mock API server.

# SIMULATION NOTE: This is a mock implementation of the Immuta REST API.
# It returns static policy/permission/data-source responses matching the
# real Immuta API shape. All data is synthetic. No real Immuta instance
# is contacted. The mock is used when no Immuta SaaS trial is available.

See spec/IMMUTA-MOCK-ADDENDUM.md for full specification.

Usage:
    python -m src.mocks.immuta_mock
    IMMUTA_MOCK_PORT=9090 python -m src.mocks.immuta_mock
"""
from __future__ import annotations

import json
import logging
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sanitised column/table names (per user preference)
# ---------------------------------------------------------------------------
# card_number → token_id, account_number → account_ref,
# client_name → entity_name, customer_id → entity_id,
# transactions → ledger_entries, fraud_signals → risk_signals,
# merchant_reference → counterparty_ref, region → jurisdiction
# ---------------------------------------------------------------------------

POLICIES: list[dict[str, Any]] = [
    {
        "id": "policy-001",
        "name": "PII Masking - General Analytics",
        "type": "masking",
        "purpose": "general_analytics",
        "actions": [
            {
                "type": "masking",
                "rules": [
                    {
                        "column": "token_id",
                        "maskType": "SHOW_LAST_4",
                        "exceptions": [{"group": "risk_investigators"}],
                    },
                    {
                        "column": "entity_name",
                        "maskType": "HASH_SHA256",
                        "exceptions": [
                            {"group": "risk_investigators"},
                            {"group": "compliance_officers"},
                        ],
                    },
                    {
                        "column": "account_ref",
                        "maskType": "HASH_SHA256",
                        "exceptions": [
                            {"group": "risk_investigators"},
                            {"group": "compliance_officers"},
                        ],
                    },
                ],
            }
        ],
        "dataSources": [
            "redshift.federation.ledger_entries",
            "s3.spectrum.ledger_entries_warm",
        ],
        "conditions": {"purposeRequired": "general_analytics"},
    },
    {
        "id": "policy-002",
        "name": "Jurisdiction Row Filter - EMEA Restriction",
        "type": "row_filter",
        "purpose": "regional_compliance",
        "actions": [
            {
                "type": "row_filter",
                "filterExpression": "jurisdiction = '${user.jurisdiction}'",
                "exemptGroups": [
                    "risk_investigators",
                    "compliance_officers",
                    "platform_admins",
                ],
            }
        ],
        "dataSources": ["redshift.federation.ledger_entries"],
        "conditions": {"userAttribute": "jurisdiction"},
    },
    {
        "id": "policy-003",
        "name": "Time-Bounded Access - Audit Window",
        "type": "subscription",
        "purpose": "external_audit",
        "actions": [
            {
                "type": "subscription",
                "group": "external_auditors",
                "accessLevel": "SELECT",
                "masking": "aggressive",
                "expiry": "2026-05-28T00:00:00Z",
            }
        ],
        "dataSources": [
            "redshift.federation.ledger_entries",
            "s3.spectrum.ledger_entries_warm",
        ],
    },
    {
        "id": "policy-004",
        "name": "Purpose-Based Unmasking - Risk Investigation",
        "type": "subscription",
        "purpose": "risk_investigation",
        "actions": [
            {
                "type": "subscription",
                "group": "risk_investigators",
                "accessLevel": "SELECT",
                "masking": "none",
            }
        ],
        "dataSources": [
            "redshift.federation.ledger_entries",
            "s3.spectrum.ledger_entries_warm",
            "snowflake.FEDERATION_DEMO.PUBLIC.ENTITIES",
        ],
    },
    {
        "id": "policy-005",
        "name": "Restricted Dataset - No External Access",
        "type": "subscription",
        "purpose": "internal_only",
        "actions": [
            {
                "type": "deny",
                "group": "external_auditors",
                "dataSources": ["databricks.federation_demo.risk_signals"],
            }
        ],
        "conditions": {
            "description": "Risk signals dataset restricted to internal users only"
        },
    },
]

PERMISSIONS: list[dict[str, Any]] = [
    {
        "user": "alice_analyst",
        "group": "data_analysts",
        "purpose": "general_analytics",
        "jurisdiction": "NA",
        "dataSources": ["redshift.federation.ledger_entries"],
        "accessLevel": "SELECT",
        "masked": True,
    },
    {
        "user": "bob_risk",
        "group": "risk_investigators",
        "purpose": "risk_investigation",
        "jurisdiction": "global",
        "dataSources": [
            "redshift.federation.ledger_entries",
            "snowflake.FEDERATION_DEMO.PUBLIC.ENTITIES",
            "databricks.federation_demo.risk_signals",
        ],
        "accessLevel": "SELECT",
        "masked": False,
    },
    {
        "user": "carol_compliance",
        "group": "compliance_officers",
        "purpose": "regional_compliance",
        "jurisdiction": "EMEA",
        "dataSources": ["redshift.federation.ledger_entries"],
        "accessLevel": "SELECT",
        "masked": True,
    },
    {
        "user": "dave_ds",
        "group": "data_scientists",
        "purpose": "general_analytics",
        "jurisdiction": "global",
        "dataSources": [
            "redshift.federation.ledger_entries",
            "databricks.federation_demo.risk_signals",
        ],
        "accessLevel": "SELECT",
        "masked": True,
    },
    {
        "user": "frank_external",
        "group": "external_auditors",
        "purpose": "external_audit",
        "jurisdiction": "global",
        "dataSources": ["redshift.federation.ledger_entries"],
        "accessLevel": "SELECT",
        "masked": True,
    },
]

DATA_SOURCES: list[dict[str, Any]] = [
    {
        "id": "ds-001",
        "name": "redshift.federation.ledger_entries",
        "platform": "redshift",
        "governanceTier": "immuta_fgac",
        "policiesApplied": ["policy-001", "policy-002", "policy-003", "policy-004"],
        "status": "active",
    },
    {
        "id": "ds-002",
        "name": "s3.spectrum.ledger_entries_warm",
        "platform": "spectrum",
        "governanceTier": "immuta_fgac",
        "policiesApplied": ["policy-001", "policy-003", "policy-004"],
        "status": "active",
    },
    {
        "id": "ds-003",
        "name": "snowflake.FEDERATION_DEMO.PUBLIC.ENTITIES",
        "platform": "snowflake",
        "governanceTier": "immuta_fgac",
        "policiesApplied": ["policy-004"],
        "status": "active",
    },
    {
        "id": "ds-004",
        "name": "databricks.federation_demo.risk_signals",
        "platform": "databricks",
        "governanceTier": "immuta_fgac",
        "policiesApplied": ["policy-005"],
        "status": "active",
    },
]


class ImmutaMockHandler(BaseHTTPRequestHandler):
    """HTTP handler serving mock Immuta API responses."""

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Immuta-Mode", "mock")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0].rstrip("/")
        if path == "/policy":
            self._send_json(POLICIES)
        elif path == "/permissions":
            self._send_json(PERMISSIONS)
        elif path == "/dataSource":
            self._send_json(DATA_SOURCES)
        elif path == "/health":
            self._send_json(
                {
                    "status": "ok",
                    "mode": "mock",
                    "policies": len(POLICIES),
                    "permissions": len(PERMISSIONS),
                    "dataSources": len(DATA_SOURCES),
                }
            )
        else:
            self._send_json({"error": "not found", "path": path}, status=404)

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info(fmt, *args)


def run_server(port: int = 8089) -> None:
    """Start the Immuta mock server."""
    server = HTTPServer(("127.0.0.1", port), ImmutaMockHandler)
    logger.info("Immuta mock server listening on port %d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down Immuta mock server")
    finally:
        server.server_close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    port = int(os.getenv("IMMUTA_MOCK_PORT", "8089"))
    run_server(port)
