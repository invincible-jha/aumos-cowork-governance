/**
 * TypeScript interfaces for the AumOS cowork-governance library.
 *
 * Mirrors the Python types defined in:
 *   aumos_cowork_governance.policies.engine
 *   aumos_cowork_governance.constitution.schema
 *   aumos_cowork_governance.dashboard.api
 *
 * All interfaces use readonly fields to match Python's Pydantic models.
 */

// ---------------------------------------------------------------------------
// Policy enumerations
// ---------------------------------------------------------------------------

/**
 * Actions that a governance policy can mandate when its conditions are met.
 * Maps to PolicyAction enum in Python.
 */
export type PolicyAction =
  | "allow"
  | "block"
  | "warn"
  | "log"
  | "approve";

/**
 * Granular permissions that can be assigned to a role.
 * Maps to Permission enum in Python.
 */
export type Permission =
  | "read"
  | "write"
  | "execute"
  | "delegate"
  | "approve"
  | "escalate";

/**
 * Strategy applied when two agents produce conflicting actions.
 * Maps to ConflictStrategy enum in Python.
 */
export type ConflictStrategy =
  | "priority_based"
  | "consensus"
  | "leader_decides"
  | "most_restrictive";

/**
 * Constraint type categories.
 * Maps to valid constraint_type values in Python.
 */
export type ConstraintType =
  | "budget_limit"
  | "rate_limit"
  | "scope_limit"
  | "safety_rule";

// ---------------------------------------------------------------------------
// Policy definition
// ---------------------------------------------------------------------------

/**
 * A single governance policy condition.
 */
export interface PolicyCondition {
  /** Dot-separated field path to evaluate from the action context. */
  readonly field: string;
  /** Comparison operator (e.g. "equals", "contains", "greater_than"). */
  readonly operator: string;
  /** The expected value to compare against. */
  readonly value: unknown;
}

/**
 * A governance policy rule that evaluates conditions and mandates an action.
 */
export interface CompliancePolicy {
  /** Human-readable policy name. */
  readonly name: string;
  /** The action to take when conditions are met. */
  readonly action: PolicyAction;
  /** Conditions that must be met (AND/OR logic per condition_logic). */
  readonly conditions: readonly PolicyCondition[];
  /** Logic for combining conditions: "AND" (default) or "OR". */
  readonly condition_logic: "AND" | "OR";
  /** Human-readable message explaining this policy's purpose. */
  readonly message: string;
  /** List of identifiers to notify when this policy triggers. */
  readonly notify: readonly string[];
}

// ---------------------------------------------------------------------------
// Policy violation
// ---------------------------------------------------------------------------

/**
 * Result of evaluating a single policy rule against an action context.
 * Maps to PolicyResult dataclass in Python.
 */
export interface PolicyViolation {
  /** Name of the policy that produced this result. */
  readonly policy_name: string;
  /** Whether the policy conditions were matched. */
  readonly matched: boolean;
  /** The action mandated by this policy. */
  readonly action: PolicyAction;
  /** Human-readable message from the policy. */
  readonly message: string;
  /** Identifiers to notify when this policy triggers. */
  readonly notify: readonly string[];
}

// ---------------------------------------------------------------------------
// Policy evaluation result
// ---------------------------------------------------------------------------

/**
 * Aggregate result of running all policies against an action context.
 * Maps to EvaluationResult dataclass in Python.
 */
export interface PolicyEvaluationResult {
  /** Whether the action is allowed (false only when a BLOCK policy matched). */
  readonly allowed: boolean;
  /** Per-policy evaluation results. */
  readonly results: readonly PolicyViolation[];
  /** Whether an APPROVE policy matched (human approval required). */
  readonly requires_approval: boolean;
  /** Name of the first BLOCK policy that triggered, or null. */
  readonly blocking_policy: string | null;
}

// ---------------------------------------------------------------------------
// Constitution schema
// ---------------------------------------------------------------------------

/**
 * Capabilities, budget limits, and tool access rules for a single agent role.
 * Maps to RoleDefinition in Python.
 */
export interface RoleDefinition {
  /** Unique identifier for this role within the constitution. */
  readonly name: string;
  /** Set of Permission values granted to this role. */
  readonly permissions: readonly Permission[];
  /** Maximum cumulative spend in USD this role may authorise, or null for no cap. */
  readonly max_budget_usd: number | null;
  /** fnmatch-style patterns of tool names this role may invoke. */
  readonly allowed_tools: readonly string[];
  /** fnmatch-style patterns of tool names this role may never invoke. */
  readonly denied_tools: readonly string[];
  /** Names of other roles this role is permitted to delegate tasks to. */
  readonly can_delegate_to: readonly string[];
  /** Names of roles whose approval is needed before sensitive actions proceed. */
  readonly requires_approval_from: readonly string[];
}

/**
 * A parameterised governance rule applying to one or more roles.
 * Maps to Constraint in Python.
 */
export interface GovernanceConstraint {
  /** Human-readable identifier for this constraint. */
  readonly name: string;
  /** Explanation of what the constraint enforces. */
  readonly description: string;
  /** The type of governance constraint. */
  readonly constraint_type: ConstraintType;
  /** Arbitrary key/value pairs that configure the constraint. */
  readonly parameters: Readonly<Record<string, unknown>>;
  /** List of role names this constraint targets. Use ["*"] for all roles. */
  readonly applies_to: readonly string[];
  /** Consequence of a violation: "warning", "error", or "critical". */
  readonly severity: "warning" | "error" | "critical";
}

/**
 * Defines when and how one role escalates to another.
 * Maps to EscalationRule in Python.
 */
export interface EscalationRule {
  /** Natural-language description of the condition that causes escalation. */
  readonly trigger: string;
  /** The role that originates the escalation. */
  readonly from_role: string;
  /** The role that receives the escalated matter. */
  readonly to_role: string;
  /** When true the escalation happens automatically; otherwise it is suggested. */
  readonly auto_escalate: boolean;
  /** Maximum wait time in seconds before escalation is auto-resolved, or null. */
  readonly timeout_seconds: number | null;
}

/**
 * A constitution rule — a single named governance principle within a Constitution.
 * Provides a named-rule abstraction layer over constraints and escalation rules.
 */
export interface ConstitutionRule {
  /** Unique rule identifier within the constitution. */
  readonly rule_id: string;
  /** Human-readable name of the rule. */
  readonly name: string;
  /** Description of what this rule enforces. */
  readonly description: string;
  /** Type of rule: "constraint", "escalation", or "permission". */
  readonly rule_type: "constraint" | "escalation" | "permission";
  /** Roles this rule applies to. */
  readonly applies_to: readonly string[];
  /** Whether violations of this rule are fatal (blocking). */
  readonly is_fatal: boolean;
}

/**
 * Top-level governance document for a multi-agent team.
 * Maps to Constitution in Python.
 */
export interface GovernanceConstitution {
  /** Semantic version string for this constitution document. */
  readonly version: string;
  /** Name of the team or project this constitution governs. */
  readonly team_name: string;
  /** Human-readable summary of the team's governance philosophy. */
  readonly description: string;
  /** Ordered list of role definitions. Order matters for PRIORITY_BASED conflict resolution. */
  readonly roles: readonly RoleDefinition[];
  /** List of governance constraints enforced at runtime. */
  readonly constraints: readonly GovernanceConstraint[];
  /** List of escalation rules defining escalation paths. */
  readonly escalation_rules: readonly EscalationRule[];
  /** The default strategy applied when agent actions conflict. */
  readonly conflict_strategy: ConflictStrategy;
  /** ISO-8601 UTC timestamp when this constitution was first created. */
  readonly created_at: string;
  /** ISO-8601 UTC timestamp of the most recent modification. */
  readonly updated_at: string;
}

// ---------------------------------------------------------------------------
// Workflow guardian
// ---------------------------------------------------------------------------

/**
 * Configuration for the WorkflowGuardian that intercepts agent actions.
 */
export interface WorkflowGuardianConfig {
  /** Whether the guardian is active. */
  readonly enabled: boolean;
  /** Agent ID this guardian is protecting. */
  readonly agent_id: string;
  /** The governance constitution to enforce. */
  readonly constitution?: GovernanceConstitution;
  /** Whether to log all evaluated actions to the audit trail. */
  readonly audit_all_actions: boolean;
  /** Maximum action cost in USD to allow without approval. */
  readonly auto_approve_below_cost_usd?: number;
}

// ---------------------------------------------------------------------------
// Governance dashboard
// ---------------------------------------------------------------------------

/** Summary of recent audit log activity. */
export interface AuditSummary {
  /** List of recent audit log entries. */
  readonly entries: readonly Readonly<Record<string, unknown>>[];
  /** Total count of audit log entries. */
  readonly total: number;
}

/** Cost tracking summary across all governed agents. */
export interface CostSummary {
  /** Total cost in USD across all tracked calls. */
  readonly total_cost_usd: number;
  /** Total token count across all tracked calls. */
  readonly total_tokens: number;
  /** Total number of LLM API calls tracked. */
  readonly call_count: number;
  /** Cost breakdown by model name. */
  readonly by_model: Readonly<Record<string, number>>;
  /** Cost breakdown by task identifier. */
  readonly by_task: Readonly<Record<string, number>>;
}

/** Aggregate governance health summary for the dashboard. */
export interface GovernanceDashboard {
  /** Whether the governance system is operating normally. */
  readonly healthy: boolean;
  /** ISO-8601 UTC timestamp of this status snapshot. */
  readonly timestamp: string;
  /** Total number of audit log entries. */
  readonly audit_count: number;
  /** Total number of loaded governance policies. */
  readonly policy_count: number;
  /** Number of pending approval requests. */
  readonly pending_approvals: number;
  /** Accumulated cost across all governed agents in USD. */
  readonly total_cost_usd: number;
}

/** A pending approval request awaiting human review. */
export interface ApprovalRequest {
  /** Unique identifier for this approval request. */
  readonly request_id: string;
  /** Name of the policy that triggered the approval requirement. */
  readonly policy_name: string;
  /** Human-readable message describing what needs approval. */
  readonly message: string;
  /** ISO-8601 UTC timestamp when this request was created. */
  readonly created_at: string;
  /** Identifiers to notify about this pending approval. */
  readonly notify: readonly string[];
  /** The action context that triggered the approval requirement. */
  readonly action_context: Readonly<Record<string, unknown>>;
}

/** Container for pending approval requests. */
export interface PendingApprovals {
  /** List of pending approval request records. */
  readonly pending: readonly ApprovalRequest[];
  /** Total count of pending approval requests. */
  readonly count: number;
}

// ---------------------------------------------------------------------------
// Workflow validation request
// ---------------------------------------------------------------------------

/** Request to validate an agent action against governance policies. */
export interface ValidateWorkflowRequest {
  /** The action context to evaluate against all loaded policies. */
  readonly action_context: Readonly<Record<string, unknown>>;
  /** Optional agent ID for scoped evaluation. */
  readonly agent_id?: string;
}

// ---------------------------------------------------------------------------
// API result wrapper
// ---------------------------------------------------------------------------

/** Standard error payload returned by the cowork-governance API. */
export interface ApiError {
  readonly error: string;
  readonly detail: string;
}

/** Result type for all client operations. */
export type ApiResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly error: ApiError; readonly status: number };
