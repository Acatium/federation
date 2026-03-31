"""ML model catalog integration for Gravitino.

Provides BedrockModelCatalog for registering AWS Bedrock foundation models
as governed assets in the Gravitino metalake alongside relational catalogs.
"""

from src.models.bedrock_catalog import BedrockModelCatalog

__all__ = ["BedrockModelCatalog"]
