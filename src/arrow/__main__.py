"""Run the full Arrow integration layer: comparison matrix + benchmarks + contract.

Usage:
    python -m src.arrow
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from src.arrow.adbc_connectors import (
    adbc_flightsql_available,
    adbc_postgresql_available,
    adbc_snowflake_available,
)
from src.arrow.benchmarks import (
    benchmarks_to_polars,
    run_benchmarks,
    save_benchmark_results,
)
from src.arrow.comparison import build_comparison_matrix, comparison_matrix_summary
from src.utils.config import CONTRACTS_DIR

logger = logging.getLogger(__name__)


def write_contract(
    *,
    comparison_ok: bool,
    paths_tested: list[str],
    adbc_available: bool,
    benchmark_path: str,
    errors: list[str] | None = None,
) -> Path:
    """Write the arrow-configured contract file.

    Args:
        comparison_ok: Whether the comparison matrix was generated successfully.
        paths_tested: List of path names that were tested.
        adbc_available: Whether ADBC drivers are available.
        benchmark_path: Path to the benchmark results JSON file.
        errors: Optional list of error messages.

    Returns:
        Path to the written contract file.
    """
    CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)

    contract = {
        "agent": "arrow",
        "status": "complete" if comparison_ok else "partial",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "comparison_matrix_generated": comparison_ok,
            "paths_tested": paths_tested,
            "adbc_available": adbc_available,
            "adbc_drivers": {
                "postgresql": adbc_postgresql_available(),
                "flightsql": adbc_flightsql_available(),
                "snowflake": adbc_snowflake_available(),
            },
            "benchmark_results": benchmark_path,
        },
    }

    if errors:
        contract["details"]["errors"] = errors

    path = CONTRACTS_DIR / "arrow-configured.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(contract, fh, indent=2)

    logger.info("Arrow contract written to %s", path)
    return path


def main() -> None:
    """Run the full Arrow integration layer."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    errors: list[str] = []
    paths_tested: list[str] = []

    # --- Comparison matrix ---
    logger.info("=== Building governance comparison matrix ===")
    comparison_ok = False
    try:
        matrix = build_comparison_matrix(limit=10_000)
        summary = comparison_matrix_summary(matrix)
        logger.info("Comparison summary: %s", summary)

        for row in matrix.iter_rows(named=True):
            paths_tested.append(row["path_name"])
            if row["status"] == "error":
                errors.append(f"{row['path_name']}: {row['error']}")

        comparison_ok = summary["paths_ok"] > 0
        logger.info("\n%s", matrix)
    except Exception as exc:
        errors.append(f"Comparison matrix failed: {exc}")
        logger.error("Comparison matrix failed: %s", exc)

    # --- Benchmarks ---
    logger.info("=== Running latency benchmarks ===")
    benchmark_path = "data/arrow_benchmarks.json"
    try:
        results = run_benchmarks(iterations=5, limit=1_000, warmup=1)
        out = save_benchmark_results(results)
        benchmark_path = str(out)

        df = benchmarks_to_polars(results)
        logger.info("\n%s", df)
    except Exception as exc:
        errors.append(f"Benchmarks failed: {exc}")
        logger.error("Benchmarks failed: %s", exc)

    # --- Contract ---
    adbc_available = (
        adbc_postgresql_available()
        or adbc_flightsql_available()
        or adbc_snowflake_available()
    )

    write_contract(
        comparison_ok=comparison_ok,
        paths_tested=paths_tested,
        adbc_available=adbc_available,
        benchmark_path=benchmark_path,
        errors=errors if errors else None,
    )

    logger.info("=== Arrow integration layer complete ===")


if __name__ == "__main__":
    main()
