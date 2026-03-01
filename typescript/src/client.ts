/**
 * HTTP client for the AumOS cowork-governance policy enforcement API.
 *
 * Delegates all HTTP transport to `@aumos/sdk-core` which provides
 * automatic retry with exponential back-off, timeout management via
 * `AbortSignal.timeout`, interceptor support, and a typed error hierarchy.
 *
 * The public-facing `ApiResult<T>` envelope is preserved for full
 * backward compatibility with existing callers.
 *
 * @example
 * ```ts
 * import { createCoworkGovernanceClient } from "@aumos/cowork-governance";
 *
 * const client = createCoworkGovernanceClient({ baseUrl: "http://localhost:8094" });
 *
 * const result = await client.checkPolicy({
 *   action_context: { action: "file_read", path: "/etc/passwd" },
 * });
 *
 * if (result.ok && !result.data.allowed) {
 *   console.log("Blocked by:", result.data.blocking_policy);
 * }
 * ```
 */

import {
  createHttpClient,
  HttpError,
  NetworkError,
  TimeoutError,
  AumosError,
  type HttpClient,
} from "@aumos/sdk-core";

import type {
  ApiResult,
  CompliancePolicy,
  GovernanceConstitution,
  GovernanceDashboard,
  PendingApprovals,
  PolicyEvaluationResult,
  ValidateWorkflowRequest,
} from "./types.js";

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

/** Configuration options for the CoworkGovernanceClient. */
export interface CoworkGovernanceClientConfig {
  /** Base URL of the cowork-governance server (e.g. "http://localhost:8094"). */
  readonly baseUrl: string;
  /** Optional request timeout in milliseconds (default: 30000). */
  readonly timeoutMs?: number;
  /** Optional extra HTTP headers sent with every request. */
  readonly headers?: Readonly<Record<string, string>>;
}

// ---------------------------------------------------------------------------
// Internal adapter
// ---------------------------------------------------------------------------

async function callApi<T>(
  operation: () => Promise<{ readonly data: T; readonly status: number }>,
): Promise<ApiResult<T>> {
  try {
    const response = await operation();
    return { ok: true, data: response.data };
  } catch (error: unknown) {
    if (error instanceof HttpError) {
      return {
        ok: false,
        error: { error: error.message, detail: String(error.body ?? "") },
        status: error.statusCode,
      };
    }
    if (error instanceof TimeoutError) {
      return {
        ok: false,
        error: { error: "Request timed out", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof NetworkError) {
      return {
        ok: false,
        error: { error: "Network error", detail: error.message },
        status: 0,
      };
    }
    if (error instanceof AumosError) {
      return {
        ok: false,
        error: { error: error.code, detail: error.message },
        status: error.statusCode ?? 0,
      };
    }
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      error: { error: "Unexpected error", detail: message },
      status: 0,
    };
  }
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the cowork-governance server. */
export interface CoworkGovernanceClient {
  /**
   * Evaluate an action context against all loaded governance policies.
   *
   * @param request - The action context to evaluate and optional agent scope.
   * @returns A PolicyEvaluationResult with allowed/blocked decision and per-policy results.
   */
  checkPolicy(
    request: ValidateWorkflowRequest,
  ): Promise<ApiResult<PolicyEvaluationResult>>;

  /**
   * Retrieve all policy violations recorded within the given time window.
   *
   * @param options - Optional filter parameters for agent, time range, and severity.
   * @returns Array of PolicyViolation records for matched policies.
   */
  getViolations(options?: {
    readonly agentId?: string;
    readonly since?: string;
    readonly limit?: number;
  }): Promise<ApiResult<readonly PolicyEvaluationResult[]>>;

  /**
   * Retrieve the governance dashboard health summary and aggregate statistics.
   *
   * @returns A GovernanceDashboard with health status, counts, and cost summary.
   */
  getDashboard(): Promise<ApiResult<GovernanceDashboard>>;

  /**
   * Validate an agent workflow action against all governance policies.
   *
   * @param request - The workflow action to validate.
   * @returns A PolicyEvaluationResult indicating whether the workflow may proceed.
   */
  validateWorkflow(
    request: ValidateWorkflowRequest,
  ): Promise<ApiResult<PolicyEvaluationResult>>;

  /**
   * Retrieve the active governance constitution for the specified team.
   *
   * @param teamName - The team whose constitution to retrieve (default: "default").
   * @returns The GovernanceConstitution defining roles, constraints, and escalation rules.
   */
  getConstitution(teamName?: string): Promise<ApiResult<GovernanceConstitution>>;

  /**
   * Upload or replace the governance constitution for a team.
   *
   * @param constitution - The full constitution document to activate.
   * @returns The stored GovernanceConstitution as confirmed by the server.
   */
  setConstitution(
    constitution: GovernanceConstitution,
  ): Promise<ApiResult<GovernanceConstitution>>;

  /**
   * Retrieve all currently loaded governance policies.
   *
   * @returns Array of CompliancePolicy records in declaration order.
   */
  getPolicies(): Promise<ApiResult<readonly CompliancePolicy[]>>;

  /**
   * Retrieve all pending approval requests awaiting human review.
   *
   * @returns A PendingApprovals object with pending requests and total count.
   */
  getPendingApprovals(): Promise<ApiResult<PendingApprovals>>;

  /**
   * Approve a pending governance request.
   *
   * @param requestId - The approval request identifier to approve.
   * @param approvedBy - Identifier of the human or system approving the request.
   * @returns An empty object on successful approval.
   */
  approveRequest(
    requestId: string,
    approvedBy: string,
  ): Promise<ApiResult<Readonly<Record<string, never>>>>;

  /**
   * Reject a pending governance request.
   *
   * @param requestId - The approval request identifier to reject.
   * @param rejectedBy - Identifier of the human or system rejecting the request.
   * @param reason - Optional human-readable reason for the rejection.
   * @returns An empty object on successful rejection.
   */
  rejectRequest(
    requestId: string,
    rejectedBy: string,
    reason?: string,
  ): Promise<ApiResult<Readonly<Record<string, never>>>>;
}

// ---------------------------------------------------------------------------
// Client factory
// ---------------------------------------------------------------------------

/**
 * Create a typed HTTP client for the cowork-governance server.
 *
 * @param config - Client configuration including base URL.
 * @returns A CoworkGovernanceClient instance.
 */
export function createCoworkGovernanceClient(
  config: CoworkGovernanceClientConfig,
): CoworkGovernanceClient {
  const http: HttpClient = createHttpClient({
    baseUrl: config.baseUrl,
    timeout: config.timeoutMs ?? 30_000,
    defaultHeaders: config.headers,
  });

  return {
    checkPolicy(
      request: ValidateWorkflowRequest,
    ): Promise<ApiResult<PolicyEvaluationResult>> {
      return callApi(() =>
        http.post<PolicyEvaluationResult>("/policies/check", request),
      );
    },

    getViolations(options?: {
      readonly agentId?: string;
      readonly since?: string;
      readonly limit?: number;
    }): Promise<ApiResult<readonly PolicyEvaluationResult[]>> {
      const queryParams: Record<string, string> = {};
      if (options?.agentId !== undefined) queryParams["agent_id"] = options.agentId;
      if (options?.since !== undefined) queryParams["since"] = options.since;
      if (options?.limit !== undefined) queryParams["limit"] = String(options.limit);
      return callApi(() =>
        http.get<readonly PolicyEvaluationResult[]>("/violations", { queryParams }),
      );
    },

    getDashboard(): Promise<ApiResult<GovernanceDashboard>> {
      return callApi(() => http.get<GovernanceDashboard>("/dashboard"));
    },

    validateWorkflow(
      request: ValidateWorkflowRequest,
    ): Promise<ApiResult<PolicyEvaluationResult>> {
      return callApi(() =>
        http.post<PolicyEvaluationResult>("/workflow/validate", request),
      );
    },

    getConstitution(teamName?: string): Promise<ApiResult<GovernanceConstitution>> {
      const queryParams: Record<string, string> = {};
      if (teamName !== undefined) queryParams["team"] = teamName;
      return callApi(() =>
        http.get<GovernanceConstitution>("/constitution", { queryParams }),
      );
    },

    setConstitution(
      constitution: GovernanceConstitution,
    ): Promise<ApiResult<GovernanceConstitution>> {
      return callApi(() =>
        http.put<GovernanceConstitution>("/constitution", constitution),
      );
    },

    getPolicies(): Promise<ApiResult<readonly CompliancePolicy[]>> {
      return callApi(() => http.get<readonly CompliancePolicy[]>("/policies"));
    },

    getPendingApprovals(): Promise<ApiResult<PendingApprovals>> {
      return callApi(() => http.get<PendingApprovals>("/approvals/pending"));
    },

    approveRequest(
      requestId: string,
      approvedBy: string,
    ): Promise<ApiResult<Readonly<Record<string, never>>>> {
      return callApi(() =>
        http.post<Readonly<Record<string, never>>>(
          `/approvals/${encodeURIComponent(requestId)}/approve`,
          { approved_by: approvedBy },
        ),
      );
    },

    rejectRequest(
      requestId: string,
      rejectedBy: string,
      reason?: string,
    ): Promise<ApiResult<Readonly<Record<string, never>>>> {
      return callApi(() =>
        http.post<Readonly<Record<string, never>>>(
          `/approvals/${encodeURIComponent(requestId)}/reject`,
          { rejected_by: rejectedBy, reason: reason ?? "" },
        ),
      );
    },
  };
}
