"""Safety model for the two-tier governance architecture.

Formalizes the safe-by-default property: for any combination of Ranger
and platform-native enforcement states, the outcome is always safe.

The safety argument:
- Ranger and platform are independent enforcement layers
- Access requires passing BOTH layers (logical AND)
- Over-permissive Ranger (stale allow) → platform blocks at source,
  provided the platform evaluates the end user (identity passthrough)
- Under-permissive Ranger (stale deny) → Ranger blocks before source
- With passthrough, the sync gap creates noise (false denials), not risk
  (false allows). With a shared service account it can create risk: the
  platform only checks what the service account can reach.

Safety is computed from the enforcement decisions, per request, so the
tests can show both the safe configuration and the one that leaks.
"""

from __future__ import annotations

import fnmatch
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


class IdentityMode(Enum):
    """Whose permissions the source platform checks when the federation layer queries it.

    This is the property the platform backstop depends on. With PASSTHROUGH the
    platform evaluates the end user's own grants, so a stale allow in Ranger is
    caught at the source. With SERVICE_ACCOUNT the connector logs in with one
    shared credential (``connection-user`` in the Trino catalog files under
    ``deploy/trino-config/``), so the platform only checks what that account can
    reach: a ceiling, not a per-user backstop. PER_GROUP_ACCOUNT sits between:
    one connector credential per group or sensitivity tier, so the ceiling is the
    group's access, and the platform catches revocations of the whole group but
    not of one person inside it.
    """

    PASSTHROUGH = "passthrough"
    PER_GROUP_ACCOUNT = "per_group_account"
    SERVICE_ACCOUNT = "service_account"


def _allows(state: EnforcementState) -> bool:
    return state in (EnforcementState.ALLOW, EnforcementState.STALE_ALLOW)


@dataclass(frozen=True)
class SyncGapOutcome:
    """Result of analyzing a Ranger×Platform state combination."""

    ranger_state: EnforcementState
    platform_state: EnforcementState
    access_granted: bool
    is_safe: bool
    # "authorized", "authorized_stale", "platform_backstop", "service_account_ceiling",
    # "fail_closed", "redundant_denial", "leak"
    outcome_type: str
    explanation: str
    identity_mode: IdentityMode = IdentityMode.PASSTHROUGH
    authorized: bool = False

    @property
    def quadrant_name(self) -> str:
        """Human-readable name for this state combination."""
        if _allows(self.ranger_state):
            if self.platform_state == EnforcementState.ALLOW:
                return "sync_current_allow"
            return "over_permissive_ranger"
        if self.platform_state == EnforcementState.DENY:
            return "both_deny"
        return "under_permissive_ranger"


def analyze_sync_gap(
    ranger_state: EnforcementState,
    platform_state: EnforcementState,
    identity_mode: IdentityMode,
    service_account_allows: bool = True,
) -> SyncGapOutcome:
    """Compute the safety outcome for a Ranger×Platform state combination.

    ``platform_state`` is the platform's decision for the *end user*: the
    authoritative answer to "should this person see this data?". What the
    platform actually enforces depends on ``identity_mode``. With passthrough it
    evaluates the end user; with a shared service account it evaluates the
    connector's credential, whose reach is ``service_account_allows``. There is
    no default: this repository deploys shared service accounts, so every caller
    has to say which configuration it is reasoning about.

    Access is granted when Ranger allows AND the platform check passes. Safety
    is computed from that, not asserted: an outcome is unsafe exactly when
    access is granted to a user the platform would not authorize.
    """
    ranger_allows = _allows(ranger_state)
    authorized = _allows(platform_state)
    enforced = authorized if identity_mode is IdentityMode.PASSTHROUGH else service_account_allows
    access_granted = ranger_allows and enforced
    is_safe = authorized or not access_granted

    if access_granted and not authorized:
        outcome_type = "leak"
        account = (
            "the group's connector account"
            if identity_mode is IdentityMode.PER_GROUP_ACCOUNT
            else "the shared service account"
        )
        explanation = (
            f"Ranger allows (stale) and the platform checks {account}, which can still "
            "read the data. The end user's revocation at the source is never consulted, "
            "so data is exposed until Ranger syncs."
        )
    elif access_granted:
        stale = EnforcementState.STALE_ALLOW in (ranger_state, platform_state)
        outcome_type = "authorized_stale" if stale else "authorized"
        explanation = "Both layers allow and the user is authorized at the source."
    elif ranger_allows and not authorized:
        outcome_type = "platform_backstop"
        explanation = (
            "Ranger allows (stale) but the platform refuses. "
            "Platform-native enforcement is the backstop: query blocked at source."
        )
    elif ranger_allows:
        outcome_type = "service_account_ceiling"
        explanation = (
            "The user is authorized, but the shared service account cannot reach the "
            "object, so the query fails at source. Noise, not risk."
        )
    elif authorized:
        outcome_type = "fail_closed"
        explanation = (
            "Ranger denies (stale) but the platform allows. "
            "User blocked at Ranger until sync catches up: fail-closed."
        )
    else:
        outcome_type = "redundant_denial"
        explanation = "Both layers deny: redundant denial, safe."

    return SyncGapOutcome(
        ranger_state=ranger_state,
        platform_state=platform_state,
        access_granted=access_granted,
        is_safe=is_safe,
        outcome_type=outcome_type,
        explanation=explanation,
        identity_mode=identity_mode,
        authorized=authorized,
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
    """A catalog sync drift scenario, evaluated through ``analyze_sync_gap``."""

    name: str
    description: str
    reason: str
    ranger_state: EnforcementState
    platform_state: EnforcementState
    # False when the source has dropped the object: no credential can read it.
    source_object_exists: bool = True

    def evaluate(self, identity_mode: IdentityMode) -> SyncGapOutcome:
        return analyze_sync_gap(
            self.ranger_state,
            self.platform_state,
            identity_mode,
            service_account_allows=self.source_object_exists,
        )

    def outcome_under(self, identity_mode: IdentityMode) -> str:
        """"fail-safe" (source blocks), "fail-closed" (Ranger blocks), "authorized" or "unsafe"."""
        result = self.evaluate(identity_mode)
        if not result.is_safe:
            return "unsafe"
        if result.access_granted:
            return "authorized"
        if result.outcome_type in ("platform_backstop", "service_account_ceiling"):
            return "fail-safe"
        return "fail-closed"

    def is_safe_under(self, identity_mode: IdentityMode) -> bool:
        return self.evaluate(identity_mode).is_safe


STALENESS_SCENARIOS: dict[str, StalenessScenario] = {
    "stale_extra_column": StalenessScenario(
        name="stale_extra_column",
        description="Ranger shows column that source dropped",
        reason="Query fails at source: the column no longer exists",
        ranger_state=EnforcementState.STALE_ALLOW,
        platform_state=EnforcementState.DENY,
        source_object_exists=False,
    ),
    "stale_missing_column": StalenessScenario(
        name="stale_missing_column",
        description="Source added column not yet in Ranger",
        reason="Ranger denies access to unknown column until sync",
        ranger_state=EnforcementState.STALE_DENY,
        platform_state=EnforcementState.ALLOW,
    ),
    "stale_extra_table": StalenessScenario(
        name="stale_extra_table",
        description="Ranger shows table that source dropped",
        reason="Query fails at source (table not found): platform backstop",
        ranger_state=EnforcementState.STALE_ALLOW,
        platform_state=EnforcementState.DENY,
        source_object_exists=False,
    ),
    "stale_missing_table": StalenessScenario(
        name="stale_missing_table",
        description="Source added table not yet in Ranger",
        reason="Table not discoverable via federation until sync",
        ranger_state=EnforcementState.STALE_DENY,
        platform_state=EnforcementState.ALLOW,
    ),
    "stale_allow_ranger": StalenessScenario(
        name="stale_allow_ranger",
        description="Ranger has stale ALLOW after source revoked",
        reason=(
            "Blocked at source only if the platform sees the end user; with a shared "
            "service account the query succeeds until Ranger syncs"
        ),
        ranger_state=EnforcementState.STALE_ALLOW,
        platform_state=EnforcementState.DENY,
    ),
    "stale_deny_ranger": StalenessScenario(
        name="stale_deny_ranger",
        description="Ranger has stale DENY after source granted",
        reason="User blocked at Ranger until sync catches up",
        ranger_state=EnforcementState.STALE_DENY,
        platform_state=EnforcementState.ALLOW,
    ),
}


# ---------------------------------------------------------------------------
# Request-level simulation over real policy data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """A user or service account, with the groups it belongs to."""

    name: str
    groups: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AccessRequest:
    """One table-level access request as it reaches the federation layer."""

    principal: Principal
    catalog: str
    schema: str
    table: str
    access: str = "select"


@dataclass(frozen=True)
class PlatformGrant:
    """A grant as the source platform holds it. ``"*"`` matches anything."""

    principal: str
    catalog: str
    schema: str
    table: str
    access: str = "select"


def _match(values: list[str] | tuple[str, ...], value: str) -> bool:
    """Ranger resource matching: ``*`` and ``?`` wildcards, case-insensitive."""
    return any(fnmatch.fnmatchcase(value.lower(), v.lower()) for v in values)


def _resource_hits(resource: dict[str, Any], value: str) -> bool:
    hit = _match(resource.get("values", []), value)
    return not hit if resource.get("isExcludes") else hit


def _item_hits(item: dict[str, Any], request: AccessRequest) -> bool:
    principal = request.principal
    who = (
        principal.name in item.get("users", [])
        or bool(principal.groups.intersection(item.get("groups", [])))
        or "public" in item.get("groups", [])
    )
    what = any(
        a.get("isAllowed", True) and a.get("type") in (request.access, "all")
        for a in item.get("accesses", [])
    )
    return who and what


def ranger_decision(policies: list[dict[str, Any]], request: AccessRequest) -> bool:
    """Evaluate Ranger access policies, in the format the extractors push.

    Covers the subset of Ranger's evaluation these policies use: resource
    wildcards and ``isExcludes``, allow and deny items with their exceptions,
    deny winning over allow, and denial when nothing allows. Not covered: policy
    conditions, validity schedules, zones, delegated admin, and column-level
    resources (evaluation is per table).
    """
    allowed = False
    for policy in policies:
        if not policy.get("isEnabled", True) or policy.get("policyType", 0) != 0:
            continue
        res = policy["resources"]
        if not (
            _resource_hits(res["catalog"], request.catalog)
            and _resource_hits(res["schema"], request.schema)
            and _resource_hits(res["table"], request.table)
        ):
            continue

        def hits(items: str, exceptions: str) -> bool:
            return any(_item_hits(i, request) for i in policy.get(items, [])) and not any(
                _item_hits(i, request) for i in policy.get(exceptions, [])
            )

        if hits("denyPolicyItems", "denyExceptions"):
            return False
        if hits("policyItems", "allowExceptions"):
            allowed = True
    return allowed


def platform_decision(grants: list[PlatformGrant], principal: Principal, request: AccessRequest) -> bool:
    """Whether the source platform lets ``principal`` perform ``request``."""
    names = {principal.name, *principal.groups}
    return any(
        g.principal in names
        and _match((g.catalog,), request.catalog)
        and _match((g.schema,), request.schema)
        and _match((g.table,), request.table)
        and g.access in (request.access, "all")
        for g in grants
    )


def simulate_request(
    request: AccessRequest,
    ranger_policies: list[dict[str, Any]],
    platform_grants: list[PlatformGrant],
    identity_mode: IdentityMode,
    service_account: Principal,
) -> SyncGapOutcome:
    """Run one request through Ranger and the source platform.

    Ranger is evaluated from its policies; the platform from its current grants,
    which are the source of truth. The platform check uses the end user under
    passthrough and ``service_account`` otherwise.
    """
    ranger = EnforcementState.ALLOW if ranger_decision(ranger_policies, request) else EnforcementState.DENY
    user = platform_decision(platform_grants, request.principal, request)
    return analyze_sync_gap(
        ranger,
        EnforcementState.ALLOW if user else EnforcementState.DENY,
        identity_mode,
        service_account_allows=platform_decision(platform_grants, service_account, request),
    )


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
