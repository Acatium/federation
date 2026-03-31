"""Bedrock IAM -> Ranger mirror policy extractor.

Maps AWS Bedrock model access (governed by IAM bedrock:InvokeModel) into
Ranger mirror policies for unified audit visibility. Ranger policies for
models are audit-only — actual enforcement is at the IAM layer.

Each model is mapped to a virtual Ranger resource:
  catalog=bedrock_models, schema=aws_bedrock, table={model_name}

Labels: source:bedrock, resource_type:model, governance_tier:platform_native

SIMULATION NOTE: Generates deterministic Ranger policies based on the known
Bedrock model inventory. In production, these would be derived from IAM
policy analysis (iam:SimulatePrincipalPolicy or Access Analyzer).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from dotenv import load_dotenv

from src.extractors.base import BaseExtractor
from src.models.bedrock_catalog import BEDROCK_MODELS

load_dotenv()

logger = logging.getLogger(__name__)

# Virtual Ranger service for model governance audit
# Uses the same Trino service since models appear in the same metalake
RANGER_MODEL_SERVICE: str = os.getenv("RANGER_SERVICE", "dev_trino")

# IAM principals that can invoke Bedrock models
# SIMULATION NOTE: In production, these would come from IAM policy analysis
BEDROCK_IAM_PRINCIPALS: dict[str, list[str]] = {
    "users": ["ml_engineer", "data_scientist"],
    "groups": ["ml_team", "federation_readers"],
}


class BedrockExtractor(BaseExtractor):
    """Extract Bedrock model access (IAM-based) into Ranger mirror policies.

    SIMULATION NOTE: Generates mirror policies for audit visibility.
    Enforcement is at the IAM layer (bedrock:InvokeModel), not at Ranger.
    """

    def __init__(self) -> None:
        super().__init__(source_name="bedrock")

    def extract_policies(self) -> list[dict[str, Any]]:
        """Generate Ranger mirror policies for each Bedrock model."""
        policies: list[dict[str, Any]] = []

        for model_def in BEDROCK_MODELS:
            model_name = model_def["name"]

            # Access policy — mirrors IAM bedrock:InvokeModel grant
            policies.append(
                self.make_access_policy(
                    name=f"bedrock_mirror_{model_name}_access",
                    database="bedrock_models",
                    table=model_name,
                    users=BEDROCK_IAM_PRINCIPALS["users"],
                    groups=BEDROCK_IAM_PRINCIPALS["groups"],
                    extra_labels=[
                        "governance_tier:platform_native",
                        "resource_type:model",
                        "enforcement:iam_only",
                        "mirror:audit_visibility",
                        f"provider:{model_def['properties'].get('provider', 'unknown')}",
                        f"model_id:{model_def['properties'].get('model_id', '')}",
                    ],
                    schema="aws_bedrock",
                )
            )

        logger.info(
            "Generated %d Bedrock mirror policies for Ranger", len(policies)
        )
        return policies


# ------------------------------------------------------------------
# Module entry point
# ------------------------------------------------------------------


def extract_and_push() -> dict[str, Any]:
    """Convenience wrapper for pipeline use."""
    extractor = BedrockExtractor()
    return extractor.extract_and_push()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    result = extract_and_push()
    logger.info("Bedrock extractor result: %s", result)
