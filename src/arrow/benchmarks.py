"""Latency benchmarks for federated data access paths.

Runs N iterations of each query path (Trino->Redshift, Direct->Redshift,
PyArrow->S3, Direct->Snowflake) and computes p50/p95/p99 latency statistics.
Results are saved to data/arrow_benchmarks.json.
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import polars as pl
from dotenv import load_dotenv

from src.utils.config import TRINO_USER
from src.utils.sql_safety import validate_identifier, validate_non_negative_int

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Benchmark result container
# ---------------------------------------------------------------------------

BENCHMARK_OUTPUT_PATH: Path = Path(__file__).resolve().parents[2] / "data" / "arrow_benchmarks.json"
DEFAULT_ITERATIONS: int = 5
DEFAULT_ROW_LIMIT: int = 1_000


@dataclass
class BenchmarkResult:
    """Latency statistics for a single data access path."""

    path_name: str
    iterations: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    mean_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    rows_per_iteration: int = 0
    errors: int = 0

    def compute_stats(self) -> None:
        """Compute percentile statistics from collected latencies."""
        valid = sorted(self.latencies_ms)
        if not valid:
            return

        self.iterations = len(valid) + self.errors
        self.min_ms = valid[0]
        self.max_ms = valid[-1]
        self.mean_ms = round(sum(valid) / len(valid), 2)
        self.p50_ms = _percentile(valid, 50)
        self.p95_ms = _percentile(valid, 95)
        self.p99_ms = _percentile(valid, 99)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-friendly dict."""
        return {
            "path_name": self.path_name,
            "iterations": self.iterations,
            "successful_iterations": len(self.latencies_ms),
            "errors": self.errors,
            "rows_per_iteration": self.rows_per_iteration,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "mean_ms": self.mean_ms,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "latencies_ms": self.latencies_ms,
        }


def _percentile(sorted_vals: list[float], pct: int) -> float:
    """Compute the pct-th percentile from a sorted list using nearest-rank."""
    if not sorted_vals:
        return 0.0
    k = max(0, math.ceil(len(sorted_vals) * pct / 100) - 1)
    return round(sorted_vals[k], 2)


# ---------------------------------------------------------------------------
# Path benchmark functions
# ---------------------------------------------------------------------------

def _bench_trino_redshift(limit: int) -> Callable[[], float]:
    """Return a callable that queries Trino→Redshift and returns latency in ms."""
    import trino

    host = os.getenv("TRINO_HOST", "")
    port = int(os.getenv("TRINO_PORT", "8080"))

    validated_limit = validate_non_negative_int(limit)

    def run() -> float:
        conn = trino.dbapi.connect(
            host=host,
            port=port,
            user=TRINO_USER,
            catalog="redshift",
            schema="federation",
        )
        try:
            cursor = conn.cursor()
            start = time.perf_counter()
            cursor.execute(
                f"SELECT * FROM redshift.federation.ledger_entries LIMIT {validated_limit}"
            )
            cursor.fetchall()
            elapsed = time.perf_counter() - start
            return round(elapsed * 1000, 2)
        finally:
            conn.close()

    return run


def _bench_direct_redshift(limit: int) -> Callable[[], float]:
    """Return a callable that queries Redshift directly and returns latency in ms."""
    import psycopg2

    host = os.getenv("REDSHIFT_HOST", "")
    port = int(os.getenv("REDSHIFT_PORT", "5439"))
    database = os.getenv("REDSHIFT_DATABASE", "dev")
    user = os.getenv("REDSHIFT_USER", "")
    password = os.getenv("REDSHIFT_PASSWORD", "")

    validated_limit = validate_non_negative_int(limit)

    def run() -> float:
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=database,
            user=user,
            password=password,
            sslmode="require",
        )
        try:
            cursor = conn.cursor()
            start = time.perf_counter()
            cursor.execute(
                f"SELECT * FROM federation.ledger_entries LIMIT {validated_limit}"
            )
            cursor.fetchall()
            elapsed = time.perf_counter() - start
            return round(elapsed * 1000, 2)
        finally:
            conn.close()

    return run


def _bench_s3_parquet(limit: int) -> Callable[[], float]:
    """Return a callable that reads S3 Parquet and returns latency in ms."""
    from src.arrow.adbc_connectors import s3_arrow_reader

    def run() -> float:
        start = time.perf_counter()
        table = s3_arrow_reader("spectrum/ledger_entries_warm/data.parquet")
        if table.num_rows > limit:
            table = table.slice(0, limit)
        elapsed = time.perf_counter() - start
        return round(elapsed * 1000, 2)

    return run


def _bench_direct_snowflake(limit: int) -> Callable[[], float]:
    """Return a callable that queries Snowflake directly and returns latency in ms."""
    import snowflake.connector

    account = os.getenv("SNOWFLAKE_ACCOUNT", "")
    user = os.getenv("SNOWFLAKE_USER", "")
    password = os.getenv("SNOWFLAKE_PASSWORD", "")
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH")
    database = os.getenv("SNOWFLAKE_DATABASE", "FEDERATION_DEMO")
    role = os.getenv("SNOWFLAKE_ROLE", "")

    validated_limit = validate_non_negative_int(limit)
    validated_db = validate_identifier(database)

    def run() -> float:
        conn = snowflake.connector.connect(
            account=account,
            user=user,
            password=password,
            warehouse=warehouse,
            database=database,
            role=role or None,
        )
        try:
            cursor = conn.cursor()
            start = time.perf_counter()
            cursor.execute(
                f"SELECT * FROM {validated_db}.PUBLIC.ENTITIES LIMIT {validated_limit}"
            )
            cursor.fetchall()
            elapsed = time.perf_counter() - start
            return round(elapsed * 1000, 2)
        finally:
            conn.close()

    return run


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_benchmarks(
    *,
    iterations: int = DEFAULT_ITERATIONS,
    limit: int = DEFAULT_ROW_LIMIT,
    include_s3: bool = True,
    warmup: int = 1,
) -> list[BenchmarkResult]:
    """Run latency benchmarks for all data access paths.

    Args:
        iterations: Number of timed iterations per path.
        limit: Row limit per query.
        include_s3: Include S3 Parquet path (needs AWS credentials).
        warmup: Number of warmup iterations (not counted in stats).

    Returns:
        List of BenchmarkResult objects with computed percentile stats.
    """
    logger.info(
        "Starting benchmarks: %d iterations, %d rows/iter, %d warmup",
        iterations, limit, warmup,
    )

    path_factories: list[tuple[str, Callable[[], Callable[[], float]]]] = [
        ("trino_redshift", lambda: _bench_trino_redshift(limit)),
        ("direct_redshift", lambda: _bench_direct_redshift(limit)),
        ("direct_snowflake", lambda: _bench_direct_snowflake(limit)),
    ]

    if include_s3:
        path_factories.insert(2, ("s3_parquet", lambda: _bench_s3_parquet(limit)))

    results: list[BenchmarkResult] = []

    for path_name, factory in path_factories:
        logger.info("Benchmarking path: %s", path_name)
        bench = BenchmarkResult(path_name=path_name, rows_per_iteration=limit)

        try:
            run_fn = factory()

            # Warmup iterations
            for w in range(warmup):
                try:
                    run_fn()
                    logger.debug("  Warmup %d/%d for %s complete", w + 1, warmup, path_name)
                except Exception as exc:  # Intentional broad catch: individual iterations must not crash benchmark
                    logger.warning("  Warmup %d failed for %s: %s", w + 1, path_name, exc)

            # Timed iterations
            for i in range(iterations):
                try:
                    latency = run_fn()
                    bench.latencies_ms.append(latency)
                    logger.debug(
                        "  %s iteration %d/%d: %.1f ms",
                        path_name, i + 1, iterations, latency,
                    )
                except Exception as exc:  # Intentional broad catch: individual iterations must not crash benchmark
                    bench.errors += 1
                    logger.warning(
                        "  %s iteration %d failed: %s", path_name, i + 1, exc
                    )

        except Exception as exc:
            bench.errors = iterations
            logger.error("Path %s setup failed entirely: %s", path_name, exc)

        bench.compute_stats()
        results.append(bench)

        logger.info(
            "  %s: p50=%.1f ms, p95=%.1f ms, p99=%.1f ms (n=%d, errors=%d)",
            path_name,
            bench.p50_ms,
            bench.p95_ms,
            bench.p99_ms,
            len(bench.latencies_ms),
            bench.errors,
        )

    return results


def save_benchmark_results(
    results: list[BenchmarkResult],
    *,
    output_path: Path | str | None = None,
) -> Path:
    """Save benchmark results to JSON.

    Args:
        results: List of BenchmarkResult objects.
        output_path: Output file path. Defaults to data/arrow_benchmarks.json.

    Returns:
        Path to the written JSON file.
    """
    out = Path(output_path) if output_path else BENCHMARK_OUTPUT_PATH
    out.parent.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "paths": [r.to_dict() for r in results],
        "summary": {
            path.path_name: {
                "p50_ms": path.p50_ms,
                "p95_ms": path.p95_ms,
                "p99_ms": path.p99_ms,
                "mean_ms": path.mean_ms,
            }
            for path in results
        },
    }

    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    logger.info("Benchmark results saved to %s", out)
    return out


def benchmarks_to_polars(results: list[BenchmarkResult]) -> pl.DataFrame:
    """Convert benchmark results to a Polars DataFrame for notebook display.

    Args:
        results: List of BenchmarkResult objects.

    Returns:
        Polars DataFrame with one row per path and percentile columns.
    """
    records = []
    for r in results:
        records.append({
            "path_name": r.path_name,
            "iterations": len(r.latencies_ms),
            "errors": r.errors,
            "rows_per_iteration": r.rows_per_iteration,
            "p50_ms": r.p50_ms,
            "p95_ms": r.p95_ms,
            "p99_ms": r.p99_ms,
            "mean_ms": r.mean_ms,
            "min_ms": r.min_ms,
            "max_ms": r.max_ms,
        })
    return pl.DataFrame(records)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """Run benchmarks and save results — entrypoint for `python -m src.arrow.benchmarks`."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    results = run_benchmarks(iterations=DEFAULT_ITERATIONS, limit=DEFAULT_ROW_LIMIT)
    out = save_benchmark_results(results)

    df = benchmarks_to_polars(results)
    logger.info("\n%s", df)
    logger.info("Results written to %s", out)


if __name__ == "__main__":
    main()
