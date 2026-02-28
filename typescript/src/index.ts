/**
 * @aumos/cowork-governance
 *
 * TypeScript client for the AumOS cowork-governance library.
 * Provides HTTP client and governance type definitions for multi-agent
 * policy enforcement, workflow validation, and constitutional governance.
 */

// Client and configuration
export type { CoworkGovernanceClient, CoworkGovernanceClientConfig } from "./client.js";
export { createCoworkGovernanceClient } from "./client.js";

// Core types
export type {
  PolicyAction,
  Permission,
  ConflictStrategy,
  ConstraintType,
  PolicyCondition,
  CompliancePolicy,
  PolicyViolation,
  PolicyEvaluationResult,
  RoleDefinition,
  GovernanceConstraint,
  EscalationRule,
  ConstitutionRule,
  GovernanceConstitution,
  WorkflowGuardianConfig,
  AuditSummary,
  CostSummary,
  GovernanceDashboard,
  ApprovalRequest,
  PendingApprovals,
  ValidateWorkflowRequest,
  ApiError,
  ApiResult,
} from "./types.js";
