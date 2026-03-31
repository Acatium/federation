"""Shared configuration constants.

Environment variables are read at point of use in each module via os.getenv().
This module holds constants that are shared across multiple modules.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Project root (two levels up from src/utils/)
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]

# Contract directory — always resolved relative to project root
CONTRACTS_DIR: Path = PROJECT_ROOT / "contracts"

# Seed for deterministic data generation (all generators default to this)
DATA_SEED: int = 42

# Offset applied to DATA_SEED for warm-tier data (avoids duplicating hot-tier)
WARM_SEED_OFFSET: int = 1

# Offset applied to DATA_SEED for cold-tier Iceberg data
COLD_SEED_OFFSET: int = 2

# Ranger service name used across extractors and tests
RANGER_SERVICE: str = os.getenv("RANGER_SERVICE", "dev_trino")

# URL schemes — allow HTTPS override for production deployments
RANGER_SCHEME: str = os.getenv("RANGER_SCHEME", "http")
GRAVITINO_SCHEME: str = os.getenv("GRAVITINO_SCHEME", "http")

# Trino user — avoid hardcoded "admin" in demo/test code
TRINO_USER: str = os.getenv("TRINO_USER", "test_user")
