"""Validates inter-agent contracts and reports build status."""
from __future__ import annotations

import json
import logging
from typing import Any

from src.utils.config import CONTRACTS_DIR

logger = logging.getLogger(__name__)

DEPENDENCY_CHAIN = {
    "connectivity-verified": [],
    "data-loaded": ["connectivity-verified"],
    "gravitino-registered": ["data-loaded"],
    "immuta-configured": ["gravitino-registered"],
    "policies-extracted": ["gravitino-registered", "immuta-configured"],
    "ranger-trino-active": ["policies-extracted"],
    "arrow-configured": ["ranger-trino-active"],
    "tests-complete": [
        "connectivity-verified", "data-loaded", "gravitino-registered",
        "immuta-configured", "policies-extracted", "ranger-trino-active",
        "arrow-configured"
    ],
}


def check_contract(name: str) -> dict[str, Any] | None:
    """Check if a contract exists and is valid."""
    path = CONTRACTS_DIR / f"{name}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("status") == "complete":
            return data
        return None
    except (json.JSONDecodeError, KeyError):
        return None


def get_ready_agents() -> list[str]:
    """Return list of agents whose dependencies are all satisfied."""
    ready = []
    for contract, deps in DEPENDENCY_CHAIN.items():
        if check_contract(contract) is not None:
            continue  # Already done
        if all(check_contract(d) is not None for d in deps):
            ready.append(contract)
    return ready


def print_status() -> None:
    """Log build status table."""
    logger.info("")
    logger.info("%-30s %-12s %-25s", "Contract", "Status", "Timestamp")
    logger.info("-" * 67)
    for contract in DEPENDENCY_CHAIN:
        data = check_contract(contract)
        if data:
            ts = data.get("timestamp", "unknown")
            logger.info("%-30s %-12s %-25s", contract, "COMPLETE", ts)
        else:
            deps = DEPENDENCY_CHAIN[contract]
            deps_met = all(check_contract(d) is not None for d in deps)
            status = "READY" if deps_met else "BLOCKED"
            logger.info("%-30s %-12s %-25s", contract, status, "—")

    ready = get_ready_agents()
    if ready:
        logger.info("Ready to start: %s", ", ".join(ready))
    else:
        complete = sum(1 for c in DEPENDENCY_CHAIN if check_contract(c))
        if complete == len(DEPENDENCY_CHAIN):
            logger.info("All agents complete!")
        else:
            logger.info("No agents ready — check blocked dependencies")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )
    print_status()
