"""Four ways to govern access across several data platforms, compared on one event.

This is a model, not a measurement: its conclusions follow from the enforcement
rules written below, and the tests check the code against those rules. The
evidence that the rules match a real deployment is the request simulator in
``safety_model.py`` and the live revoke-at-source test in
``tests/validation/test_scenario3_the_failure_modes.py``.

The event is a revocation: a person loses access to a table at the pattern's own
source of truth. For MIRROR that is the platform; for PUSH_DOWN the central
policy store; for CATALOG_AUTHORITY the catalog; for ENGINE_ENFORCEMENT the
engine's policy store. If people revoke at the platform instead, engine
enforcement inherits the mirror's sync window.
Each pattern is scored on how long that person can still read the data afterwards
(the exposure window), on how that depends on the identity the connector presents,
and on which kinds of estate the pattern can reach.

Timings are inputs, not facts about any product: ``Timings`` holds labelled example
values. Change them and run ``python -m src.governance.patterns`` to regenerate the
comparison table in the README.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from enum import Enum

from src.governance.safety_model import EnforcementState, IdentityMode, analyze_sync_gap


class Pattern(Enum):
    MIRROR = "Mirror platform grants into one policy store"
    PUSH_DOWN = "Author centrally, push down to native controls"
    CATALOG_AUTHORITY = "One catalog is the authority"
    ENGINE_ENFORCEMENT = "Enforce in the query engine"


class RevocationScope(Enum):
    """Who loses access: one person, or a whole group they belong to."""

    PERSON = "person"
    GROUP = "group"


@dataclass(frozen=True)
class Timings:
    """Example latencies, in seconds. Assumptions to vary, not product defaults."""

    batch_sync: float = 900.0  # mirror pulls every platform's grants on a schedule
    event_sync: float = 30.0  # mirror is fed by the platforms' grant-change events
    push: float = 60.0  # central store writes the change into each native control
    credential_ttl: float = 3600.0  # lifetime of storage credentials a catalog vends
    decision_cache: float = 60.0  # how long the engine reuses a policy decision


@dataclass(frozen=True)
class Scenario:
    pattern: Pattern
    identity: IdentityMode
    scope: RevocationScope = RevocationScope.PERSON
    event_driven: bool = False  # MIRROR only: event-fed rather than batch sync
    # MIRROR only: the platform vends storage credentials (Unity Catalog here) rather
    # than checking each query, so its own revocation waits for those to expire.
    vended_credentials: bool = False


@dataclass(frozen=True)
class Exposure:
    """How long the revoked person keeps access, and what finally cuts it off."""

    scenario: Scenario
    expected_seconds: float
    worst_seconds: float
    closed_by: str

    @property
    def never_closes(self) -> bool:
        return math.isinf(self.worst_seconds)


def _sees_the_person(identity: IdentityMode, scope: RevocationScope) -> bool:
    """Whether the enforcing layer can tell the revoked person from everyone else."""
    if identity is IdentityMode.PASSTHROUGH:
        return True
    return identity is IdentityMode.PER_GROUP_ACCOUNT and scope is RevocationScope.GROUP


def _window(scenario: Scenario, seconds: float, closed_by: str) -> Exposure:
    # A revocation lands at a random point in a periodic window: half on average.
    return Exposure(scenario, seconds / 2, seconds, closed_by)


def _never(scenario: Scenario, where: str) -> Exposure:
    return Exposure(scenario, math.inf, math.inf, f"not closed on {where}")


def exposure_after_revocation(scenario: Scenario, timings: Timings = Timings()) -> Exposure:
    """Compute the exposure window for one pattern, identity model and revocation."""
    pattern, identity = scenario.pattern, scenario.identity

    if pattern is Pattern.MIRROR:
        # The platform revoked; Ranger still allows until it syncs. Whether the
        # platform's own check stops the query is the sync-gap model's answer.
        outcome = analyze_sync_gap(
            EnforcementState.STALE_ALLOW,
            EnforcementState.DENY,
            identity,
            service_account_allows=not _sees_the_person(identity, scenario.scope),
        )
        sync = (
            Exposure(scenario, timings.event_sync, timings.event_sync, "mirror, on the change event")
            if scenario.event_driven
            else _window(scenario, timings.batch_sync, "mirror, at the next sync")
        )
        if outcome.access_granted:
            return sync
        if not scenario.vended_credentials:
            return Exposure(scenario, 0.0, 0.0, "platform, immediately")
        # The platform has revoked, but credentials it already vended stay valid;
        # whichever comes first, their expiry or the mirror's sync, cuts access.
        ttl = _window(scenario, timings.credential_ttl, "vended credentials expiring")
        return ttl if ttl.worst_seconds <= sync.worst_seconds else sync

    if pattern is Pattern.PUSH_DOWN:
        # Native controls are written per person. A connector that logs in as a
        # shared account is never matched by them.
        if not _sees_the_person(identity, scenario.scope):
            return _never(scenario, "shared-connector paths")
        return Exposure(scenario, timings.push, timings.push, "native control, once pushed")

    if pattern is Pattern.CATALOG_AUTHORITY:
        # New credential requests are refused at once; credentials already vended
        # stay valid until they expire.
        if not _sees_the_person(identity, scenario.scope):
            return _never(scenario, "engines that authenticate as a shared principal")
        return _window(scenario, timings.credential_ttl, "vended credentials expiring")

    # ENGINE_ENFORCEMENT: the engine knows the end user whatever credential it uses
    # downstream, so identity to the source does not matter for traffic it carries.
    return _window(scenario, timings.decision_cache, "engine, when its cached decision expires")


@dataclass(frozen=True)
class Coverage:
    open_formats: str
    cloud_warehouses: str
    on_prem_databases: str
    mainframe: str
    blind_spot: str


COVERAGE: dict[Pattern, Coverage] = {
    Pattern.MIRROR: Coverage(
        open_formats="Yes",
        cloud_warehouses="Yes (Snowflake, Redshift extractors here)",
        on_prem_databases="Yes, from grant views (Oracle `DBA_TAB_PRIVS`, DB2 `SYSCAT.TABAUTH`, SQL Server `sys.database_permissions`)",
        mainframe="DB2 for z/OS catalog grants; RACF profiles for IMS and VSAM",
        blind_spot="Visibility, not enforcement: safe per person only with passthrough",
    ),
    Pattern.PUSH_DOWN: Coverage(
        open_formats="Yes (Unity Catalog ABAC, Polaris RBAC)",
        cloud_warehouses="Yes (row access and masking policies; Redshift RLS and masking)",
        on_prem_databases="Where native row and column controls exist (Oracle VPD, DB2 RCAC, SQL Server RLS)",
        mainframe="DB2 for z/OS RCAC; IMS and VSAM only at RACF dataset level",
        blind_spot="Anything native controls cannot express; shared-account paths",
    ),
    Pattern.CATALOG_AUTHORITY: Coverage(
        open_formats="Yes: the pattern's home",
        cloud_warehouses="Through Iceberg tables, or as foreign catalogs behind one connection credential",
        on_prem_databases="As foreign catalogs behind one connection credential",
        mainframe="No",
        blind_spot="Everything not registered in the catalog",
    ),
    Pattern.ENGINE_ENFORCEMENT: Coverage(
        open_formats="Yes",
        cloud_warehouses="Yes, for queries through the engine",
        on_prem_databases="Yes, for queries through the engine",
        mainframe="Where a connector exists",
        blind_spot="Applications that connect to the source directly",
    ),
}


def _fmt(seconds: float) -> str:
    if math.isinf(seconds):
        return "never"
    if seconds == 0:
        return "0"
    if seconds < 120:
        return f"{seconds:g} s"
    return f"{seconds / 60:g} min"


def _cell(exposure: Exposure) -> str:
    if exposure.never_closes:
        return "**never**"
    if exposure.worst_seconds == 0:
        return "0"
    if exposure.expected_seconds == exposure.worst_seconds:
        return _fmt(exposure.worst_seconds)
    return f"≤ {_fmt(exposure.worst_seconds)} (avg {_fmt(exposure.expected_seconds)})"


IDENTITY_COLUMNS = (
    ("Passthrough", IdentityMode.PASSTHROUGH),
    ("Per-group accounts", IdentityMode.PER_GROUP_ACCOUNT),
    ("Shared account", IdentityMode.SERVICE_ACCOUNT),
)


def exposure_table(timings: Timings = Timings()) -> str:
    """Markdown table: exposure after one person's access is revoked."""
    rows = [
        ("Mirror, batch sync", Scenario(Pattern.MIRROR, IdentityMode.PASSTHROUGH)),
        ("Mirror, event-driven sync", Scenario(Pattern.MIRROR, IdentityMode.PASSTHROUGH, event_driven=True)),
        (
            "Mirror, batch sync, over vended credentials",
            Scenario(Pattern.MIRROR, IdentityMode.PASSTHROUGH, vended_credentials=True),
        ),
        ("Push down to native controls", Scenario(Pattern.PUSH_DOWN, IdentityMode.PASSTHROUGH)),
        ("Catalog as authority", Scenario(Pattern.CATALOG_AUTHORITY, IdentityMode.PASSTHROUGH)),
        ("Enforce in the engine", Scenario(Pattern.ENGINE_ENFORCEMENT, IdentityMode.PASSTHROUGH)),
    ]
    header = "| Pattern | " + " | ".join(name for name, _ in IDENTITY_COLUMNS) + " |"
    lines = [header, "|" + "---|" * (len(IDENTITY_COLUMNS) + 1)]
    for label, base in rows:
        cells = [
            _cell(exposure_after_revocation(replace(base, identity=mode), timings))
            for _, mode in IDENTITY_COLUMNS
        ]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def coverage_table() -> str:
    """Markdown table: which estates each pattern reaches."""
    lines = [
        "| Pattern | Open formats | Cloud warehouses | On-prem databases | Mainframe | Blind spot |",
        "|---|---|---|---|---|---|",
    ]
    for pattern, c in COVERAGE.items():
        lines.append(
            f"| {pattern.value} | {c.open_formats} | {c.cloud_warehouses} | "
            f"{c.on_prem_databases} | {c.mainframe} | {c.blind_spot} |"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(exposure_table())
    print()
    print(coverage_table())
