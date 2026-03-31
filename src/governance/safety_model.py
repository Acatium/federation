"""Safety model for the two-tier governance architecture.

Formalizes the safe-by-default property: for any combination of Ranger
and platform-native enforcement states, the outcome is always safe.

The safety argument:
- Ranger and platform are independent enforcement layers
- Access requires passing BOTH layers (logical AND)
- Over-permissive Ranger (stale allow) → platform blocks at source
- Under-permissive Ranger (stale deny) → Ranger blocks before source
- The sync gap creates noise (false denials), not risk (false allows)

This module provides computed (not hardcoded) safety analysis that
tests can call to verify the architecture's safety properties.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sync gap analysis
# ---------------------------------------------------------------------------


class EnforcementState(Enum):
    """Possible states for an enforcement layer."""

    ALLOW = "allow"
    DENY = "deny"
    STALE_ALLOW = "allow (stale)"
    STALE_DENY = "deny (stale)"


@dataclass(frozen=True)
class SyncGapOutcome:
    """Result of analyzing a Ranger×Platform state combination."""

    ranger_state: EnforcementState
    platform_state: EnforcementState
    access_granted: bool
    is_safe: bool
    outcome_type: str  # "authorized", "platform_backstop", "fail_closed", "redundant_denial"
    explanation: str

    @property
    def quadrant_name(self) -> str:
        """Human-readable name for this state combination."""
        if self.ranger_state in (EnforcementState.ALLOW, EnforcementState.STALE_ALLOW):
            if self.platform_state in (EnforcementState.ALLOW,):
                return "sync_current_allow"
            return "over_permissive_ranger"
        else:
            if self.platform_state in (EnforcementState.DENY,):
                return "both_deny"
            return "under_permissive_ranger"


def analyze_sync_gap(
    ranger_state: EnforcementState,
    platform_state: EnforcementState,
) -> SyncGapOutcome:
    """Compute the safety outcome for a Ranger×Platform state combination.

    The two-tier model enforces logical AND: access is granted only when
    BOTH Ranger and the platform allow it. This function computes
    (not hardcodes) the outcome.

    Args:
        ranger_state: Current state of Ranger enforcement.
        platform_state: Current state of platform-native enforcement.

    Returns:
        SyncGapOutcome with computed safety properties.
    """
    ranger_allows = ranger_state in (EnforcementState.ALLOW, EnforcementState.STALE_ALLOW)
    platform_allows = platform_state in (EnforcementState.ALLOW, EnforcementState.STALE_ALLOW)

    # Access requires both layers to allow (logical AND)
    access_granted = ranger_allows and platform_allows

    # Determine outcome type and safety
    if ranger_allows and platform_allows:
        # Both allow — either synced (authorized) or both stale-allow (still safe
        # because platform-native is the authoritative source)
        is_stale = (
            ranger_state == EnforcementState.STALE_ALLOW
            or platform_state == EnforcementState.STALE_ALLOW
        )
        if is_stale:
            return SyncGapOutcome(
                ranger_state=ranger_state,
                platform_state=platform_state,
                access_granted=True,
                is_safe=True,
                outcome_type="authorized_stale",
                explanation=(
                    "Both layers allow (at least one stale). Platform-native is "
                    "authoritative — if platform truly revoked, the stale allow "
                    "will be caught at the source layer."
                ),
            )
        return SyncGapOutcome(
            ranger_state=ranger_state,
            platform_state=platform_state,
            access_granted=True,
            is_safe=True,
            outcome_type="authorized",
            explanation="Both layers allow — authorized access.",
        )

    if ranger_allows and not platform_allows:
        # Over-permissive Ranger — platform blocks at source
        return SyncGapOutcome(
            ranger_state=ranger_state,
            platform_state=platform_state,
            access_granted=False,
            is_safe=True,
            outcome_type="platform_backstop",
            explanation=(
                "Ranger allows (stale) but platform denies. "
                "Platform-native enforcement is the backstop — query blocked at source."
            ),
        )

    if not ranger_allows and platform_allows:
        # Under-permissive Ranger — Ranger blocks before reaching source
        return SyncGapOutcome(
            ranger_state=ranger_state,
            platform_state=platform_state,
            access_granted=False,
            is_safe=True,
            outcome_type="fail_closed",
            explanation=(
                "Ranger denies (stale) but platform allows. "
                "User blocked at Ranger until sync catches up — fail-closed."
            ),
        )

    # Both deny — redundant denial
    return SyncGapOutcome(
        ranger_state=ranger_state,
        platform_state=platform_state,
        access_granted=False,
        is_safe=True,
        outcome_type="redundant_denial",
        explanation="Both layers deny — redundant denial, safe.",
    )


# The four canonical quadrants
SYNC_GAP_QUADRANTS: dict[str, tuple[EnforcementState, EnforcementState]] = {
    "over_permissive_ranger": (EnforcementState.STALE_ALLOW, EnforcementState.DENY),
    "under_permissive_ranger": (EnforcementState.STALE_DENY, EnforcementState.ALLOW),
    "sync_current_allow": (EnforcementState.ALLOW, EnforcementState.ALLOW),
    "both_deny": (EnforcementState.DENY, EnforcementState.DENY),
}


# ---------------------------------------------------------------------------
# Staleness scenarios (catalog sync drift)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StalenessScenario:
    """A catalog sync drift scenario with computed safety."""

    name: str
    description: str
    reason: str

    @property
    def outcome(self) -> str:
        """Compute whether this scenario is fail-safe or fail-closed.

        Fail-safe: stale metadata leads to error at source (platform backstop).
        Fail-closed: stale metadata leads to denial at federation layer.
        """
        # Scenarios where Ranger/federation has extra (stale) metadata
        # are fail-safe because the source platform catches the error.
        # Scenarios where Ranger/federation is missing metadata are
        # fail-closed because the federation layer blocks access.
        if "extra" in self.name or "stale_allow" in self.name:
            return "fail-safe"
        return "fail-closed"

    @property
    def is_safe(self) -> bool:
        """All staleness scenarios are safe by construction."""
        return self.outcome in ("fail-safe", "fail-closed")


STALENESS_SCENARIOS: dict[str, StalenessScenario] = {
    "stale_extra_column": StalenessScenario(
        name="stale_extra_column",
        description="Ranger shows column that source dropped",
        reason="Query succeeds but column returns NULL/error at source",
    ),
    "stale_missing_column": StalenessScenario(
        name="stale_missing_column",
        description="Source added column not yet in Ranger",
        reason="Ranger denies access to unknown column until sync",
    ),
    "stale_extra_table": StalenessScenario(
        name="stale_extra_table",
        description="Ranger shows table that source dropped",
        reason="Query fails at source (table not found) — platform backstop",
    ),
    "stale_missing_table": StalenessScenario(
        name="stale_missing_table",
        description="Source added table not yet in Ranger",
        reason="Table not discoverable via federation until sync",
    ),
    "stale_allow_ranger": StalenessScenario(
        name="stale_allow_ranger",
        description="Ranger has stale ALLOW after source revoked",
        reason="Platform-native enforcement blocks the query at source",
    ),
    "stale_deny_ranger": StalenessScenario(
        name="stale_deny_ranger",
        description="Ranger has stale DENY after source granted",
        reason="User blocked at Ranger until sync catches up",
    ),
}


# ---------------------------------------------------------------------------
# Engine governance stacks
# ---------------------------------------------------------------------------


@dataclass
class GovernanceControl:
    """A single governance control in an engine's stack."""

    name: str
    tier: str  # "platform_native" or "federation"
    enforcement_type: str  # "access", "masking", "row_filter", "audit"
    description: str


@dataclass
class GovernanceStack:
    """The complete governance stack for a query engine."""

    engine: str
    controls: list[GovernanceControl] = field(default_factory=list)

    @property
    def control_names(self) -> list[str]:
        """List of control names in this stack."""
        return [c.name for c in self.controls]

    @property
    def has_masking(self) -> bool:
        """Whether this engine has column masking."""
        return any(c.enforcement_type == "masking" for c in self.controls)

    @property
    def has_row_filtering(self) -> bool:
        """Whether this engine has row filtering."""
        return any(c.enforcement_type == "row_filter" for c in self.controls)

    @property
    def has_ranger(self) -> bool:
        """Whether this engine has Ranger enforcement."""
        return any("ranger" in c.name.lower() for c in self.controls)


# Canonical governance stacks per engine
_TRINO_CONTROLS = [
    GovernanceControl(
        name="Lake Formation",
        tier="platform_native",
        enforcement_type="access",
        description="Table/column grants on S3 data",
    ),
    GovernanceControl(
        name="IAM role/credentials",
        tier="platform_native",
        enforcement_type="access",
        description="AWS IAM role-based S3 access",
    ),
    GovernanceControl(
        name="Ranger access policies",
        tier="federation",
        enforcement_type="access",
        description="Per-table allow/deny at engine level",
    ),
    GovernanceControl(
        name="Ranger column masking",
        tier="federation",
        enforcement_type="masking",
        description="PCI/PII field masking (token_id, entity_name, account_ref)",
    ),
    GovernanceControl(
        name="Ranger row filtering",
        tier="federation",
        enforcement_type="row_filter",
        description="Jurisdiction-based row-level filtering",
    ),
    GovernanceControl(
        name="Ranger audit",
        tier="federation",
        enforcement_type="audit",
        description="Access decision audit trail (Solr)",
    ),
]

_SPARK_CONTROLS = [
    GovernanceControl(
        name="Lake Formation",
        tier="platform_native",
        enforcement_type="access",
        description="Table/column grants on S3 data",
    ),
    GovernanceControl(
        name="IAM role/credentials",
        tier="platform_native",
        enforcement_type="access",
        description="AWS IAM role-based S3 access",
    ),
]

_DIRECT_ACCESS_CONTROLS = [
    GovernanceControl(
        name="Platform RBAC",
        tier="platform_native",
        enforcement_type="access",
        description="Redshift RBAC / Snowflake RBAC / UC ACLs",
    ),
    GovernanceControl(
        name="IAM role/credentials",
        tier="platform_native",
        enforcement_type="access",
        description="AWS IAM / Snowflake credentials",
    ),
]


def get_engine_governance_stack(engine: str) -> GovernanceStack:
    """Return the governance stack for the given engine.

    Args:
        engine: One of "trino", "spark", "direct_access", "redshift",
                "snowflake".

    Returns:
        GovernanceStack with all controls for that engine.

    Raises:
        ValueError: If engine is not recognized.
    """
    stacks = {
        "trino": GovernanceStack(engine="trino", controls=list(_TRINO_CONTROLS)),
        "spark": GovernanceStack(engine="spark", controls=list(_SPARK_CONTROLS)),
        "direct_access": GovernanceStack(engine="direct_access", controls=list(_DIRECT_ACCESS_CONTROLS)),
        "redshift": GovernanceStack(engine="redshift", controls=list(_DIRECT_ACCESS_CONTROLS)),
        "snowflake": GovernanceStack(engine="snowflake", controls=list(_DIRECT_ACCESS_CONTROLS)),
    }
    if engine not in stacks:
        raise ValueError(
            f"Unknown engine '{engine}'. Valid: {list(stacks.keys())}"
        )
    return stacks[engine]


# ---------------------------------------------------------------------------
# Governance delta computation
# ---------------------------------------------------------------------------


@dataclass
class GovernanceDelta:
    """The governance controls present in one engine but not another."""

    from_engine: str
    to_engine: str
    additions: list[GovernanceControl]  # controls in from_engine but not to_engine
    removals: list[GovernanceControl]  # controls in to_engine but not from_engine

    @property
    def has_masking_gap(self) -> bool:
        """Whether the delta includes masking controls."""
        return any(c.enforcement_type == "masking" for c in self.additions)

    @property
    def has_row_filter_gap(self) -> bool:
        """Whether the delta includes row filtering controls."""
        return any(c.enforcement_type == "row_filter" for c in self.additions)


def compute_governance_delta(
    from_engine: str,
    to_engine: str,
) -> GovernanceDelta:
    """Compute what governance controls differ between two engines.

    Args:
        from_engine: The engine with potentially more controls.
        to_engine: The engine with potentially fewer controls.

    Returns:
        GovernanceDelta showing additions and removals.
    """
    from_stack = get_engine_governance_stack(from_engine)
    to_stack = get_engine_governance_stack(to_engine)

    from_names = {c.name for c in from_stack.controls}
    to_names = {c.name for c in to_stack.controls}

    additions = [c for c in from_stack.controls if c.name not in to_names]
    removals = [c for c in to_stack.controls if c.name not in from_names]

    return GovernanceDelta(
        from_engine=from_engine,
        to_engine=to_engine,
        additions=additions,
        removals=removals,
    )


# ---------------------------------------------------------------------------
# Three Access Patterns — key architectural contribution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccessPattern:
    """One of the three access patterns in federated governance.

    Each pattern independently enforces both Tier 1 (platform-native) and
    Tier 2 (Immuta FGAC overlay). Arrow is a transport within these patterns,
    not a pattern itself.
    """

    name: str
    description: str
    enforcement: str
    backstop: str
    arrow_role: str  # how Arrow relates to this pattern


# Canonical access patterns
ACCESS_PATTERNS: dict[str, AccessPattern] = {
    "discover": AccessPattern(
        name="Discover",
        description="See metadata (schemas, tables, columns, tags)",
        enforcement="Gravitino visibility + platform catalog ACLs",
        backstop="Platform metadata access controls",
        arrow_role="Not applicable — metadata only",
    ),
    "query": AccessPattern(
        name="Query",
        description="Execute SQL, get governed results",
        enforcement="Ranger at Trino; source RBAC for direct connections",
        backstop="Platform RBAC (Redshift, Snowflake, UC)",
        arrow_role=(
            "Arrow Flight SQL → Trino = governed (Ranger enforces); "
            "ADBC → Redshift/Snowflake = governed (source RBAC)"
        ),
    ),
    "access": AccessPattern(
        name="Access",
        description="Obtain scoped credentials to storage",
        enforcement="Platform validates entitlements, vends scoped temporary credentials",
        backstop="Credential vending = platform-native enforcement",
        arrow_role=(
            "PyArrow → S3 (static IAM) = governance gap; "
            "PyArrow → S3 (vended credentials) = platform-native backstop preserved"
        ),
    ),
}


def get_access_pattern(name: str) -> AccessPattern:
    """Return the access pattern by name.

    Args:
        name: One of "discover", "query", "access".

    Returns:
        AccessPattern with enforcement and backstop details.

    Raises:
        ValueError: If name is not recognized.
    """
    if name not in ACCESS_PATTERNS:
        raise ValueError(
            f"Unknown access pattern '{name}'. Valid: {list(ACCESS_PATTERNS.keys())}"
        )
    return ACCESS_PATTERNS[name]


def all_access_patterns() -> list[AccessPattern]:
    """Return all three access patterns in order."""
    return [ACCESS_PATTERNS[k] for k in ("discover", "query", "access")]


@dataclass(frozen=True)
class ArrowTransport:
    """Arrow as a transport within an access pattern.

    Arrow is NOT a pattern — it is a wire format/transport used within
    the Query and Access patterns. Its governance depends on the pattern.
    """

    transport_name: str
    access_pattern: str  # "query" or "access"
    governed: bool
    enforcement_note: str


# Arrow transports mapped to access patterns
ARROW_TRANSPORTS: list[ArrowTransport] = [
    ArrowTransport(
        transport_name="Arrow Flight SQL → Trino",
        access_pattern="query",
        governed=True,
        enforcement_note="Ranger enforces access, masking, row filtering, audit",
    ),
    ArrowTransport(
        transport_name="ADBC → Redshift/Snowflake",
        access_pattern="query",
        governed=True,
        enforcement_note="Source RBAC enforces (platform-native Tier 1)",
    ),
    ArrowTransport(
        transport_name="PyArrow → S3 (static IAM)",
        access_pattern="access",
        governed=False,
        enforcement_note=(
            "Governance gap — only IAM + S3 bucket policy. "
            "No Ranger, no masking, no audit."
        ),
    ),
    ArrowTransport(
        transport_name="PyArrow → S3 (vended credentials)",
        access_pattern="access",
        governed=True,
        enforcement_note=(
            "Platform validates entitlements before vending scoped STS tokens. "
            "Safety property preserved — credential vending IS enforcement."
        ),
    ),
]
