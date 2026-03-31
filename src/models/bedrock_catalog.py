"""Bedrock Model Catalog — register AWS Bedrock models in Gravitino.

Creates a MODEL-type catalog in the Gravitino metalake to provide unified
metadata governance across data assets AND ML models. Each Bedrock model
is registered with its ARN, version aliases, and governance tags.

Governance: Tier 1 (platform_native). Bedrock model access is governed by
IAM ``bedrock:InvokeModel`` permissions. Ranger mirrors these as audit-only
policies — enforcement is at the IAM layer, not at a query engine.

SIMULATION NOTE: This module creates catalog/schema/model metadata in
Gravitino via its REST API. Actual Bedrock model invocation is not performed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Gravitino REST API
GRAVITINO_HOST: str = os.getenv("GRAVITINO_HOST", "localhost")
GRAVITINO_PORT: str = os.getenv("GRAVITINO_PORT", "8090")
GRAVITINO_SCHEME: str = os.getenv("GRAVITINO_SCHEME", "http")
GRAVITINO_BASE_URL: str = f"{GRAVITINO_SCHEME}://{GRAVITINO_HOST}:{GRAVITINO_PORT}"
METALAKE: str = "federation"

# AWS
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-2")
AWS_ACCOUNT_ID: str = os.getenv("AWS_ACCOUNT_ID", "")

# Bedrock model definitions
BEDROCK_MODELS: list[dict[str, Any]] = [
    {
        "name": "claude_3_sonnet",
        "comment": "Anthropic Claude 3 Sonnet — balanced performance and cost",
        "properties": {
            "provider": "anthropic",
            "model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
            "modality": "text",
            "governance_tier": "platform_native",
            "max_tokens": "4096",
        },
        "versions": [
            {
                "version": "v1.0",
                "aliases": ["production"],
                "uri": f"arn:aws:bedrock:{AWS_REGION}::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0",
                "properties": {"status": "GA", "release_date": "2024-02-29"},
            }
        ],
    },
    {
        "name": "titan_text_express",
        "comment": "Amazon Titan Text Express — low-latency text generation",
        "properties": {
            "provider": "amazon",
            "model_id": "amazon.titan-text-express-v1",
            "modality": "text",
            "governance_tier": "platform_native",
            "max_tokens": "8192",
        },
        "versions": [
            {
                "version": "v1.0",
                "aliases": ["production", "staging"],
                "uri": f"arn:aws:bedrock:{AWS_REGION}::foundation-model/amazon.titan-text-express-v1",
                "properties": {"status": "GA", "release_date": "2023-09-28"},
            }
        ],
    },
    {
        "name": "claude_3_haiku",
        "comment": "Anthropic Claude 3 Haiku — fastest and most compact",
        "properties": {
            "provider": "anthropic",
            "model_id": "anthropic.claude-3-haiku-20240307-v1:0",
            "modality": "text",
            "governance_tier": "platform_native",
            "max_tokens": "4096",
        },
        "versions": [
            {
                "version": "v1.0",
                "aliases": ["staging"],
                "uri": f"arn:aws:bedrock:{AWS_REGION}::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
                "properties": {"status": "GA", "release_date": "2024-03-07"},
            }
        ],
    },
]


class BedrockModelCatalog:
    """Register and manage Bedrock models in Gravitino's model catalog.

    SIMULATION NOTE: Uses Gravitino REST API to create a MODEL-type catalog,
    schema, and model entries. If Gravitino is unreachable, falls back to
    returning the model definitions without API calls.
    """

    def __init__(self) -> None:
        self.base_url: str = GRAVITINO_BASE_URL
        self.metalake: str = METALAKE
        self.catalog_name: str = "bedrock_models"
        self.schema_name: str = "aws_bedrock"
        self.models: list[dict[str, Any]] = BEDROCK_MODELS

    def register_all(self) -> dict[str, Any]:
        """Register the model catalog, schema, and all models in Gravitino.

        Returns a summary dict with registration results.
        """
        results: dict[str, Any] = {
            "catalog": self.catalog_name,
            "schema": self.schema_name,
            "models_registered": 0,
            "models_failed": 0,
            "status": "complete",
        }

        try:
            self._create_catalog()
            self._create_schema()

            for model_def in self.models:
                try:
                    self._register_model(model_def)
                    results["models_registered"] += 1
                except Exception as exc:
                    logger.error(
                        "Failed to register model '%s': %s",
                        model_def["name"],
                        exc,
                    )
                    results["models_failed"] += 1

        except requests.ConnectionError:
            # SIMULATION NOTE: Gravitino not reachable — return simulated results
            logger.warning(
                "Gravitino not reachable at %s — returning simulated model catalog",
                self.base_url,
            )
            results["models_registered"] = len(self.models)
            results["status"] = "simulated"

        except Exception as exc:
            logger.error("Model catalog registration failed: %s", exc)
            results["status"] = "error"
            results["error"] = str(exc)

        logger.info("Bedrock model catalog registration: %s", results)
        return results

    def _create_catalog(self) -> None:
        """Create the bedrock_models catalog (type MODEL) in Gravitino."""
        url = f"{self.base_url}/api/metalakes/{self.metalake}/catalogs"
        payload = {
            "name": self.catalog_name,
            "type": "MODEL",
            "comment": "AWS Bedrock foundation model registry",
            "properties": {
                "governance_tier": "platform_native",
                "provider": "aws_bedrock",
            },
        }
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 409:
            logger.info("Model catalog '%s' already exists", self.catalog_name)
        elif resp.status_code in (200, 201):
            logger.info("Created model catalog '%s'", self.catalog_name)
        else:
            resp.raise_for_status()

    def _create_schema(self) -> None:
        """Create the aws_bedrock schema inside the model catalog."""
        url = (
            f"{self.base_url}/api/metalakes/{self.metalake}"
            f"/catalogs/{self.catalog_name}/schemas"
        )
        payload = {
            "name": self.schema_name,
            "comment": "AWS Bedrock foundation models",
            "properties": {
                "provider": "aws_bedrock",
                "region": AWS_REGION,
            },
        }
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 409:
            logger.info("Schema '%s' already exists", self.schema_name)
        elif resp.status_code in (200, 201):
            logger.info("Created schema '%s'", self.schema_name)
        else:
            resp.raise_for_status()

    def _register_model(self, model_def: dict[str, Any]) -> None:
        """Register a single model with versions and aliases."""
        model_name = model_def["name"]
        url = (
            f"{self.base_url}/api/metalakes/{self.metalake}"
            f"/catalogs/{self.catalog_name}/schemas/{self.schema_name}"
            f"/models"
        )
        payload = {
            "name": model_name,
            "comment": model_def.get("comment", ""),
            "properties": model_def.get("properties", {}),
        }
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 409:
            logger.info("Model '%s' already exists", model_name)
        elif resp.status_code in (200, 201):
            logger.info("Registered model '%s'", model_name)
        else:
            resp.raise_for_status()

        # Register versions
        for version_def in model_def.get("versions", []):
            self._register_version(model_name, version_def)

    def _register_version(
        self, model_name: str, version_def: dict[str, Any]
    ) -> None:
        """Register a model version with URI and aliases."""
        url = (
            f"{self.base_url}/api/metalakes/{self.metalake}"
            f"/catalogs/{self.catalog_name}/schemas/{self.schema_name}"
            f"/models/{model_name}/versions"
        )
        payload = {
            "uri": version_def["uri"],
            "aliases": version_def.get("aliases", []),
            "comment": f"Version {version_def['version']}",
            "properties": version_def.get("properties", {}),
        }
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code == 409:
            logger.info(
                "Model version '%s/%s' already exists",
                model_name,
                version_def["version"],
            )
        elif resp.status_code in (200, 201):
            logger.info(
                "Registered model version '%s/%s'",
                model_name,
                version_def["version"],
            )
        else:
            # Non-critical — model exists but version registration may not be supported
            logger.warning(
                "Could not register version '%s/%s': %s %s",
                model_name,
                version_def["version"],
                resp.status_code,
                resp.text[:200],
            )

    # ------------------------------------------------------------------
    # Query helpers (for tests)
    # ------------------------------------------------------------------

    def list_models(self) -> list[dict[str, Any]]:
        """List all models in the bedrock_models catalog.

        Returns model definitions from the local registry if Gravitino
        is unreachable.
        """
        url = (
            f"{self.base_url}/api/metalakes/{self.metalake}"
            f"/catalogs/{self.catalog_name}/schemas/{self.schema_name}"
            f"/models"
        )
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                return resp.json().get("identifiers", [])
        except requests.ConnectionError:
            pass

        # Fallback: return local definitions
        return [{"name": m["name"]} for m in self.models]

    def get_model(self, model_name: str) -> dict[str, Any]:
        """Get a single model's metadata.

        Falls back to local definitions if Gravitino is unreachable.
        """
        url = (
            f"{self.base_url}/api/metalakes/{self.metalake}"
            f"/catalogs/{self.catalog_name}/schemas/{self.schema_name}"
            f"/models/{model_name}"
        )
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                return resp.json()
        except requests.ConnectionError:
            pass

        # Fallback: return local definition
        for m in self.models:
            if m["name"] == model_name:
                return m
        return {}

    def get_catalog_info(self) -> dict[str, Any]:
        """Get catalog metadata from Gravitino.

        Returns a simulated response if Gravitino is unreachable.
        """
        url = (
            f"{self.base_url}/api/metalakes/{self.metalake}"
            f"/catalogs/{self.catalog_name}"
        )
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                return resp.json()
        except requests.ConnectionError:
            pass

        # Fallback: simulated catalog info
        return {
            "name": self.catalog_name,
            "type": "MODEL",
            "comment": "AWS Bedrock foundation model registry (simulated)",
            "properties": {
                "governance_tier": "platform_native",
                "provider": "aws_bedrock",
            },
        }


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def register_bedrock_models() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    catalog = BedrockModelCatalog()
    return catalog.register_all()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = register_bedrock_models()
    logger.info("Bedrock model catalog result: %s", result)
