"""Constitution schema — Pydantic v2 models for multi-agent governance.

Defines the data structures that make up a team constitution: roles, constraints,
escalation rules, and the top-level ``Constitution`` document.

Example
-------
>>> from aumos_cowork_governance.constitution.schema import Constitution, Permission
>>> yaml_text = open("team_constitution.yaml").read()
>>> constitution = Constitution.from_yaml(yaml_text)
>>> role = constitution.get_role("orchestrator")
>>> Permission.DELEGATE in role.permissions
True
"""
from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from enum import Enum

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Permission(str, Enum):
    """Granular permissions that can be assigned to a role."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELEGATE = "delegate"
    APPROVE = "approve"
    ESCALATE = "escalate"


class ConflictStrategy(str, Enum):
    """Strategy applied when two agents produce conflicting actions."""

    PRIORITY_BASED = "priority_based"
    CONSENSUS = "consensus"
    LEADER_DECIDES = "leader_decides"
    MOST_RESTRICTIVE = "most_restrictive"


# ---------------------------------------------------------------------------
# Role definition
# ---------------------------------------------------------------------------


class RoleDefinition(BaseModel):
    """Capabilities, budget limits, and tool access rules for a single agent role.

    Attributes
    ----------
    name:
        Unique identifier for this role within the constitution.
    permissions:
        Set of ``Permission`` values granted to this role.
    max_budget_usd:
        Maximum cumulative spend in USD this role is allowed to authorise.
        ``None`` means no budget cap is enforced at the role level.
    allowed_tools:
        fnmatch-style patterns of tool names this role may invoke.
        An empty list means all tools are allowed (subject to ``denied_tools``).
    denied_tools:
        fnmatch-style patterns of tool names this role may never invoke.
        Denial takes priority over ``allowed_tools``.
    can_delegate_to:
        Names of other roles this role is permitted to delegate tasks to.
    requires_approval_from:
        Names of roles whose approval is needed before sensitive actions
        performed by this role proceed.
    """

    name: str
    permissions: list[Permission] = Field(default_factory=list)
    max_budget_usd: float | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    can_delegate_to: list[str] = Field(default_factory=list)
    requires_approval_from: list[str] = Field(default_factory=list)

    @field_validator("max_budget_usd")
    @classmethod
    def budget_must_be_positive(cls, value: float | None) -> float | None:
        if value is not None and value < 0:
            raise ValueError("max_budget_usd must be >= 0")
        return value


# ---------------------------------------------------------------------------
# Constraint
# ---------------------------------------------------------------------------


_VALID_CONSTRAINT_TYPES: frozenset[str] = frozenset(
    {"budget_limit", "rate_limit", "scope_limit", "safety_rule"}
)
_VALID_SEVERITIES: frozenset[str] = frozenset({"warning", "error", "critical"})


class Constraint(BaseModel):
    """A parameterised governance rule that applies to one or more roles.

    Attributes
    ----------
    name:
        Human-readable identifier for this constraint.
    description:
        Explanation of what the constraint enforces.
    constraint_type:
        One of ``budget_limit``, ``rate_limit``, ``scope_limit``, ``safety_rule``.
    parameters:
        Arbitrary key/value pairs that configure the constraint (e.g. ``{"limit_usd": 100}``).
    applies_to:
        List of role names this constraint targets.  Use ``["*"]`` for all roles.
    severity:
        Consequence of a violation: ``warning``, ``error``, or ``critical``.
    """

    name: str
    description: str
    constraint_type: str
    parameters: dict[str, object] = Field(default_factory=dict)
    applies_to: list[str] = Field(default_factory=lambda: ["*"])
    severity: str = "error"

    @field_validator("constraint_type")
    @classmethod
    def validate_constraint_type(cls, value: str) -> str:
        if value not in _VALID_CONSTRAINT_TYPES:
            raise ValueError(
                f"constraint_type must be one of {sorted(_VALID_CONSTRAINT_TYPES)}, got {value!r}"
            )
        return value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {value!r}"
            )
        return value


# ---------------------------------------------------------------------------
# Escalation rule
# ---------------------------------------------------------------------------


class EscalationRule(BaseModel):
    """Defines when and how one role escalates to another.

    Attributes
    ----------
    trigger:
        Natural-language description of the condition that causes escalation.
    from_role:
        The role that originates the escalation.
    to_role:
        The role that receives the escalated matter.
    auto_escalate:
        When ``True`` the escalation happens automatically; when ``False`` it
        is suggested to the originating agent.
    timeout_seconds:
        Optional maximum wait time before escalation is auto-resolved or
        abandoned.  ``None`` means no timeout.
    """

    trigger: str
    from_role: str
    to_role: str
    auto_escalate: bool = False
    timeout_seconds: float | None = None

    @field_validator("timeout_seconds")
    @classmethod
    def timeout_must_be_positive(cls, value: float | None) -> float | None:
        if value is not None and value <= 0:
            raise ValueError("timeout_seconds must be > 0")
        return value


# ---------------------------------------------------------------------------
# Constitution
# ---------------------------------------------------------------------------


class Constitution(BaseModel):
    """Top-level governance document for a multi-agent team.

    A ``Constitution`` captures the complete governance policy for a named team:
    which roles exist, what constraints apply, how escalation flows, and how
    conflicts between agents are resolved.

    Attributes
    ----------
    version:
        Semantic version string for this constitution document.
    team_name:
        Name of the team or project this constitution governs.
    description:
        Human-readable summary of the team's purpose and governance philosophy.
    roles:
        Ordered list of ``RoleDefinition`` objects.  Order matters for
        ``PRIORITY_BASED`` conflict resolution — earlier = higher priority.
    constraints:
        List of ``Constraint`` objects that are enforced at runtime.
    escalation_rules:
        List of ``EscalationRule`` objects that define escalation paths.
    conflict_strategy:
        The default strategy applied when agent actions conflict.
    created_at:
        UTC timestamp when this constitution was first created.
    updated_at:
        UTC timestamp of the most recent modification.
    """

    version: str = "1.0.0"
    team_name: str
    description: str = ""
    roles: list[RoleDefinition] = Field(default_factory=list)
    constraints: list[Constraint] = Field(default_factory=list)
    escalation_rules: list[EscalationRule] = Field(default_factory=list)
    conflict_strategy: ConflictStrategy = ConflictStrategy.PRIORITY_BASED
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    def get_role(self, name: str) -> RoleDefinition | None:
        """Return the ``RoleDefinition`` with ``name``, or ``None`` if absent."""
        for role in self.roles:
            if role.name == name:
                return role
        return None

    # ------------------------------------------------------------------
    # Internal consistency validation
    # ------------------------------------------------------------------

    def validate_constitution(self) -> list[str]:
        """Check internal consistency and return a list of error messages.

        Checks performed
        ----------------
        - All role names referenced in ``can_delegate_to`` exist.
        - All role names referenced in ``requires_approval_from`` exist.
        - All role names referenced in escalation rules exist.
        - All role names referenced in constraints exist (unless ``"*"``).
        - No circular delegation chains exist.

        Returns
        -------
        list[str]
            Empty list when the constitution is consistent; otherwise each
            element describes one problem.
        """
        errors: list[str] = []
        known_role_names: set[str] = {role.name for role in self.roles}

        # Validate role cross-references.
        for role in self.roles:
            for delegatee in role.can_delegate_to:
                if delegatee not in known_role_names:
                    errors.append(
                        f"Role '{role.name}' can_delegate_to unknown role '{delegatee}'"
                    )
            for approver in role.requires_approval_from:
                if approver not in known_role_names:
                    errors.append(
                        f"Role '{role.name}' requires_approval_from unknown role '{approver}'"
                    )

        # Validate escalation rule references.
        for rule in self.escalation_rules:
            if rule.from_role not in known_role_names:
                errors.append(
                    f"EscalationRule trigger='{rule.trigger}' references unknown from_role '{rule.from_role}'"
                )
            if rule.to_role not in known_role_names:
                errors.append(
                    f"EscalationRule trigger='{rule.trigger}' references unknown to_role '{rule.to_role}'"
                )

        # Validate constraint role references.
        for constraint in self.constraints:
            for role_name in constraint.applies_to:
                if role_name != "*" and role_name not in known_role_names:
                    errors.append(
                        f"Constraint '{constraint.name}' applies_to unknown role '{role_name}'"
                    )

        # Detect circular delegation using DFS.
        circular_errors = self._detect_circular_delegation(known_role_names)
        errors.extend(circular_errors)

        return errors

    def _detect_circular_delegation(self, known_role_names: set[str]) -> list[str]:
        """Return error messages for every cycle found in delegation graph."""
        # Build adjacency map (only for known roles to avoid KeyError).
        adjacency: dict[str, list[str]] = {name: [] for name in known_role_names}
        for role in self.roles:
            for delegatee in role.can_delegate_to:
                if delegatee in known_role_names:
                    adjacency[role.name].append(delegatee)

        # DFS cycle detection — collect all cycle descriptions.
        errors: list[str] = []
        visited: set[str] = set()
        in_stack: set[str] = set()

        def dfs(node: str, path: list[str]) -> None:
            visited.add(node)
            in_stack.add(node)
            path.append(node)
            for neighbour in adjacency.get(node, []):
                if neighbour not in visited:
                    dfs(neighbour, path)
                elif neighbour in in_stack:
                    cycle_start = path.index(neighbour)
                    cycle = path[cycle_start:] + [neighbour]
                    errors.append(
                        "Circular delegation detected: " + " -> ".join(cycle)
                    )
            path.pop()
            in_stack.discard(node)

        for role_name in known_role_names:
            if role_name not in visited:
                dfs(role_name, [])

        return errors

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain Python dict (JSON-compatible)."""
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Constitution":
        """Deserialise from a plain Python dict."""
        return cls.model_validate(data)

    def to_yaml(self) -> str:
        """Serialise to a YAML string."""
        return yaml.dump(
            self.to_dict(),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

    @classmethod
    def from_yaml(cls, yaml_str: str) -> "Constitution":
        """Deserialise from a YAML string."""
        data: dict[str, object] = yaml.safe_load(yaml_str) or {}
        return cls.from_dict(data)

    # ------------------------------------------------------------------
    # Starter template
    # ------------------------------------------------------------------

    @classmethod
    def starter(cls, team_name: str) -> "Constitution":
        """Return a minimal starter constitution for *team_name*.

        The template includes:
        - An ``orchestrator`` role with full permissions
        - A ``worker`` role with read/write/execute permissions
        - A ``reviewer`` role with read and approve permissions
        - A basic budget constraint
        - One escalation rule from worker to orchestrator
        """
        now = datetime.now(tz=timezone.utc)
        return cls(
            version="1.0.0",
            team_name=team_name,
            description=f"Starter constitution for team '{team_name}'.",
            roles=[
                RoleDefinition(
                    name="orchestrator",
                    permissions=list(Permission),
                    max_budget_usd=1000.0,
                    allowed_tools=["*"],
                    denied_tools=[],
                    can_delegate_to=["worker", "reviewer"],
                    requires_approval_from=[],
                ),
                RoleDefinition(
                    name="worker",
                    permissions=[
                        Permission.READ,
                        Permission.WRITE,
                        Permission.EXECUTE,
                        Permission.ESCALATE,
                    ],
                    max_budget_usd=100.0,
                    allowed_tools=["*"],
                    denied_tools=["admin_*"],
                    can_delegate_to=[],
                    requires_approval_from=["orchestrator"],
                ),
                RoleDefinition(
                    name="reviewer",
                    permissions=[Permission.READ, Permission.APPROVE],
                    max_budget_usd=None,
                    allowed_tools=["read_*", "search_*"],
                    denied_tools=[],
                    can_delegate_to=[],
                    requires_approval_from=[],
                ),
            ],
            constraints=[
                Constraint(
                    name="global_budget_cap",
                    description="No single role may exceed its budget allocation.",
                    constraint_type="budget_limit",
                    parameters={"enforce_per_role": True},
                    applies_to=["*"],
                    severity="critical",
                ),
                Constraint(
                    name="worker_rate_limit",
                    description="Workers are limited to 60 tool calls per minute.",
                    constraint_type="rate_limit",
                    parameters={"calls_per_minute": 60},
                    applies_to=["worker"],
                    severity="warning",
                ),
            ],
            escalation_rules=[
                EscalationRule(
                    trigger="Worker encounters an action requiring approval",
                    from_role="worker",
                    to_role="orchestrator",
                    auto_escalate=True,
                    timeout_seconds=300.0,
                ),
            ],
            conflict_strategy=ConflictStrategy.PRIORITY_BASED,
            created_at=now,
            updated_at=now,
        )

    # ------------------------------------------------------------------
    # Model config
    # ------------------------------------------------------------------

    model_config = {"frozen": False}
