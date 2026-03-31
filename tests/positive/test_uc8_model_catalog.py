"""UC-8: Bedrock Model Catalog in Gravitino.

Verifies that AWS Bedrock foundation models are registered in Gravitino
as a MODEL-type catalog, providing unified metadata governance across
data assets AND ML models in the same metalake.

Governance: Tier 1 (platform_native). Model access is governed by IAM
bedrock:InvokeModel permissions. Ranger provides audit-only mirror policies.
"""

import logging
from typing import Any

import pytest
import requests

logger = logging.getLogger(__name__)


class TestModelCatalog:
    """Verify Bedrock models are registered in Gravitino model catalog."""

    def test_model_catalog_exists(
        self, gravitino_model_catalog: dict[str, Any]
    ) -> None:
        """The bedrock_models catalog should exist as type MODEL.

        Gravitino 1.0+ supports MODEL catalogs alongside RELATIONAL catalogs,
        enabling unified governance of data and ML assets.
        """
        assert gravitino_model_catalog, "Model catalog info is empty"
        catalog_type = gravitino_model_catalog.get("type", "")
        # Handle nested response format
        if not catalog_type:
            catalog_type = (
                gravitino_model_catalog.get("catalog", {}).get("type", "")
            )

        assert catalog_type.upper() == "MODEL", (
            f"Expected catalog type 'MODEL', got '{catalog_type}'"
        )
        logger.info("Model catalog exists with type=%s", catalog_type)

    def test_model_catalog_in_metalake_listing(
        self, gravitino_base_url: str
    ) -> None:
        """bedrock_models should appear alongside relational catalogs.

        The metalake listing includes both data catalogs (Hive, Redshift,
        Snowflake, Iceberg) and model catalogs (Bedrock).
        """
        url = f"{gravitino_base_url}/api/metalakes/federation/catalogs"
        try:
            resp = requests.get(url, timeout=30)
        except requests.ConnectionError as exc:
            pytest.skip(f"Gravitino not reachable: {exc}")
        if resp.status_code != 200:
            pytest.skip(f"Cannot list Gravitino catalogs (HTTP {resp.status_code})")
        data = resp.json()
        names = [i["name"] for i in data.get("identifiers", [])]
        logger.info("Metalake catalogs: %s", names)
        assert "bedrock_models" in names, (
            f"bedrock_models not found in metalake catalogs: {names}"
        )

    def test_models_registered(
        self, bedrock_models: list[dict[str, Any]]
    ) -> None:
        """At least 2 Bedrock models should be registered.

        The demo registers Claude 3 Sonnet, Titan Text Express, and
        Claude 3 Haiku — three representative foundation models.
        """
        assert len(bedrock_models) >= 2, (
            f"Expected at least 2 Bedrock models, got {len(bedrock_models)}"
        )
        model_names = [m["name"] for m in bedrock_models]
        logger.info("Registered Bedrock models: %s", model_names)

    def test_model_has_governance_properties(
        self, bedrock_models: list[dict[str, Any]]
    ) -> None:
        """Each model should have governance_tier and provider properties.

        These properties enable unified governance queries across
        data assets and ML models.
        """
        for model in bedrock_models:
            props = model.get("properties", {})
            assert "governance_tier" in props, (
                f"Model '{model['name']}' missing governance_tier property"
            )
            assert props["governance_tier"] == "platform_native", (
                f"Model '{model['name']}' governance_tier should be "
                f"'platform_native', got '{props['governance_tier']}'"
            )
            assert "provider" in props, (
                f"Model '{model['name']}' missing provider property"
            )
            logger.info(
                "Model '%s': governance_tier=%s, provider=%s",
                model["name"],
                props["governance_tier"],
                props["provider"],
            )

    def test_model_version_has_bedrock_arn(
        self, bedrock_models: list[dict[str, Any]]
    ) -> None:
        """Each model version URI should be a valid Bedrock ARN.

        The ARN format is: arn:aws:bedrock:{region}::foundation-model/{model_id}
        """
        for model in bedrock_models:
            versions = model.get("versions", [])
            assert len(versions) > 0, (
                f"Model '{model['name']}' has no versions"
            )
            for version in versions:
                uri = version.get("uri", "")
                assert uri.startswith("arn:aws:bedrock:"), (
                    f"Model '{model['name']}' version '{version['version']}' "
                    f"URI should be a Bedrock ARN, got: '{uri}'"
                )
                assert "foundation-model/" in uri, (
                    f"Bedrock ARN should contain 'foundation-model/', got: '{uri}'"
                )
                logger.info(
                    "Model '%s' version '%s' ARN: %s",
                    model["name"],
                    version["version"],
                    uri,
                )

    def test_model_aliases_work(
        self, bedrock_models: list[dict[str, Any]]
    ) -> None:
        """Model versions should have production/staging aliases.

        Aliases allow consumers to reference 'production' or 'staging'
        without knowing the specific version number.
        """
        all_aliases: set[str] = set()
        for model in bedrock_models:
            for version in model.get("versions", []):
                aliases = version.get("aliases", [])
                all_aliases.update(aliases)
                logger.info(
                    "Model '%s' version '%s' aliases: %s",
                    model["name"],
                    version["version"],
                    aliases,
                )

        assert "production" in all_aliases, (
            f"Expected 'production' alias across models, got: {all_aliases}"
        )
        logger.info("All model aliases: %s", sorted(all_aliases))

    def test_model_discovery_api(self) -> None:
        """BedrockModelCatalog.list_models() should return all registered models.

        This provides a discovery API for finding available foundation models
        within the governed metalake.
        """
        from src.models.bedrock_catalog import BedrockModelCatalog

        catalog = BedrockModelCatalog()
        models = catalog.list_models()
        assert len(models) >= 2, (
            f"Expected at least 2 models from discovery API, got {len(models)}"
        )
        names = [m.get("name", "") for m in models]
        logger.info("Model discovery returned: %s", names)
        assert all(name for name in names), "All models should have names"

    def test_unified_catalog_spans_data_and_models(
        self, gravitino_base_url: str
    ) -> None:
        """The metalake should contain both RELATIONAL and MODEL catalogs.

        This proves unified governance across data and ML assets.
        """
        url = f"{gravitino_base_url}/api/metalakes/federation/catalogs"
        try:
            resp = requests.get(url, timeout=30)
        except requests.ConnectionError as exc:
            pytest.skip(f"Gravitino not reachable: {exc}")
        if resp.status_code != 200:
            pytest.skip(f"Cannot list Gravitino catalogs (HTTP {resp.status_code})")
        data = resp.json()
        names = [i["name"] for i in data.get("identifiers", [])]

        has_model = "bedrock_models" in names
        has_relational = any(
            n in names for n in ["hive", "redshift", "snowflake", "iceberg_s3"]
        )

        assert has_model and has_relational, (
            f"Expected both MODEL and RELATIONAL catalogs in metalake. "
            f"Model={has_model}, Relational={has_relational}, catalogs={names}"
        )
        logger.info(
            "UNIFIED CATALOG: Metalake spans data catalogs AND model "
            "catalogs: %s",
            names,
        )
