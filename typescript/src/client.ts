/**
 * HTTP client for the AumOS cowork-governance policy enforcement API.
 *
 * Uses the Fetch API (available natively in Node 18+, browsers, and Deno).
 * No external dependencies required.
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

import type {
  ApiError,
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
// Internal helpers
// ---------------------------------------------------------------------------

async function fetchJson<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<ApiResult<T>> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    clearTimeout(timeoutId);

    const body = await response.json() as unknown;

    if (!response.ok) {
      const errorBody = body as Partial<ApiError>;
      return {
        ok: false,
        error: {
          error: errorBody.error ?? "Unknown error",
          detail: errorBody.detail ?? "",
        },
        status: response.status,
      };
    }

    return { ok: true, data: body as T };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: { error: "Network error", detail: message },
      status: 0,
    };
  }
}

function buildHeaders(
  extraHeaders: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...extraHeaders,
  };
}

// ---------------------------------------------------------------------------
// Client interface
// ---------------------------------------------------------------------------

/** Typed HTTP client for the cowork-governance server. */
export interface CoworkGovernanceClient {
  /**
   * Evaluate an action context against all loaded governance policies.
   *
   * The first BLOCK policy that matches terminates evaluation and sets
   * allowed=false.  APPROVE policies set requires_approval=true without blocking.
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
   * Equivalent to checkPolicy but returns a richer validation object
   * suitable for pre-execution workflow gates.
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
  const { baseUrl, timeoutMs = 30_000, headers: extraHeaders } = config;
  const baseHeaders = buildHeaders(extraHeaders);

  return {
    async checkPolicy(
      request: ValidateWorkflowRequest,
    ): Promise<ApiResult<PolicyEvaluationResult>> {
      return fetchJson<PolicyEvaluationResult>(
        `${baseUrl}/policies/check`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async getViolations(options?: {
      readonly agentId?: string;
      readonly since?: string;
      readonly limit?: number;
    }): Promise<ApiResult<readonly PolicyEvaluationResult[]>> {
      const params = new URLSearchParams();
      if (options?.agentId !== undefined) {
        params.set("agent_id", options.agentId);
      }
      if (options?.since !== undefined) {
        params.set("since", options.since);
      }
      if (options?.limit !== undefined) {
        params.set("limit", String(options.limit));
      }
      const queryString = params.toString();
      const url = queryString
        ? `${baseUrl}/violations?${queryString}`
        : `${baseUrl}/violations`;
      return fetchJson<readonly PolicyEvaluationResult[]>(
        url,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async getDashboard(): Promise<ApiResult<GovernanceDashboard>> {
      return fetchJson<GovernanceDashboard>(
        `${baseUrl}/dashboard`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async validateWorkflow(
      request: ValidateWorkflowRequest,
    ): Promise<ApiResult<PolicyEvaluationResult>> {
      return fetchJson<PolicyEvaluationResult>(
        `${baseUrl}/workflow/validate`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify(request),
        },
        timeoutMs,
      );
    },

    async getConstitution(
      teamName?: string,
    ): Promise<ApiResult<GovernanceConstitution>> {
      const params = new URLSearchParams();
      if (teamName !== undefined) {
        params.set("team", teamName);
      }
      const queryString = params.toString();
      const url = queryString
        ? `${baseUrl}/constitution?${queryString}`
        : `${baseUrl}/constitution`;
      return fetchJson<GovernanceConstitution>(
        url,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async setConstitution(
      constitution: GovernanceConstitution,
    ): Promise<ApiResult<GovernanceConstitution>> {
      return fetchJson<GovernanceConstitution>(
        `${baseUrl}/constitution`,
        {
          method: "PUT",
          headers: baseHeaders,
          body: JSON.stringify(constitution),
        },
        timeoutMs,
      );
    },

    async getPolicies(): Promise<ApiResult<readonly CompliancePolicy[]>> {
      return fetchJson<readonly CompliancePolicy[]>(
        `${baseUrl}/policies`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async getPendingApprovals(): Promise<ApiResult<PendingApprovals>> {
      return fetchJson<PendingApprovals>(
        `${baseUrl}/approvals/pending`,
        { method: "GET", headers: baseHeaders },
        timeoutMs,
      );
    },

    async approveRequest(
      requestId: string,
      approvedBy: string,
    ): Promise<ApiResult<Readonly<Record<string, never>>>> {
      return fetchJson<Readonly<Record<string, never>>>(
        `${baseUrl}/approvals/${encodeURIComponent(requestId)}/approve`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify({ approved_by: approvedBy }),
        },
        timeoutMs,
      );
    },

    async rejectRequest(
      requestId: string,
      rejectedBy: string,
      reason?: string,
    ): Promise<ApiResult<Readonly<Record<string, never>>>> {
      return fetchJson<Readonly<Record<string, never>>>(
        `${baseUrl}/approvals/${encodeURIComponent(requestId)}/reject`,
        {
          method: "POST",
          headers: baseHeaders,
          body: JSON.stringify({ rejected_by: rejectedBy, reason: reason ?? "" }),
        },
        timeoutMs,
      );
    },
  };
}

