"""Multi-user isolation sandbox for co-work sessions.

Provides per-user resource quotas, namespace isolation, and access control
so that multiple users sharing a co-work session cannot interfere with one
another's state, resources, or actions.

Key classes
-----------
ResourceQuota     : Per-user resource limits (actions, memory, CPU-tokens).
IsolationPolicy   : Rules governing cross-user access.
UserSandbox       : Isolated execution context for a single user.
UserSandboxManager: Registry and enforcement layer for all user sandboxes.
IsolationViolation: Exception raised when a policy boundary is crossed.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IsolationViolation(Exception):
    """Raised when an operation violates isolation policy.

    Attributes
    ----------
    user_id:
        The user who triggered the violation.
    target_user_id:
        The user whose resource was accessed (may equal user_id for quota).
    reason:
        Human-readable description of the violation.
    """

    def __init__(self, user_id: str, target_user_id: str, reason: str) -> None:
        self.user_id = user_id
        self.target_user_id = target_user_id
        self.reason = reason
        super().__init__(
            f"Isolation violation by '{user_id}' targeting '{target_user_id}': {reason}"
        )


# ---------------------------------------------------------------------------
# Resource quota
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceQuota:
    """Per-user resource limits for a co-work session.

    Attributes
    ----------
    max_actions_per_minute:
        Maximum number of recorded actions allowed per 60-second window.
    max_memory_entries:
        Maximum number of key-value items in the user's namespace store.
    max_cpu_tokens:
        Abstract CPU-token budget (arbitrary units; caller defines semantics).
    max_concurrent_tools:
        Maximum number of tools the user may invoke simultaneously.
    """

    max_actions_per_minute: int = 60
    max_memory_entries: int = 1_000
    max_cpu_tokens: int = 10_000
    max_concurrent_tools: int = 5


# ---------------------------------------------------------------------------
# Isolation policy
# ---------------------------------------------------------------------------


class CrossUserAccess(str, Enum):
    """Cross-user access modes."""

    DENY_ALL = "deny_all"          # No cross-user reads or writes
    READ_ONLY = "read_only"        # Users may read other namespaces, no writes
    ALLOW_ALL = "allow_all"        # Full cross-user access (trusted context)


@dataclass(frozen=True)
class IsolationPolicy:
    """Rules governing user isolation within a session.

    Attributes
    ----------
    session_id:
        The session this policy applies to.
    cross_user_access:
        Global default cross-user access mode.
    enforce_quotas:
        When True, ResourceQuota limits are actively enforced.
    allow_shared_read_namespaces:
        Set of namespace keys any user may read regardless of access mode.
    audit_violations:
        When True, violations are logged before raising.
    """

    session_id: str
    cross_user_access: CrossUserAccess = CrossUserAccess.DENY_ALL
    enforce_quotas: bool = True
    allow_shared_read_namespaces: frozenset[str] = field(
        default_factory=frozenset
    )
    audit_violations: bool = True

    def allows_cross_read(self, namespace: str) -> bool:
        """Return True if *namespace* may be read by any user.

        Parameters
        ----------
        namespace:
            The namespace key to check.

        Returns
        -------
        bool
            True when cross-user reads are allowed for this namespace.
        """
        if self.cross_user_access == CrossUserAccess.ALLOW_ALL:
            return True
        if namespace in self.allow_shared_read_namespaces:
            return True
        return self.cross_user_access == CrossUserAccess.READ_ONLY

    def allows_cross_write(self) -> bool:
        """Return True if cross-user writes are globally permitted."""
        return self.cross_user_access == CrossUserAccess.ALLOW_ALL


# ---------------------------------------------------------------------------
# User sandbox
# ---------------------------------------------------------------------------


class UserSandbox:
    """Isolated execution context for a single user.

    Maintains the user's private namespace store, action counters, CPU-token
    budget, and active tool set.  All mutation methods enforce quota limits
    when ``enforce_quotas`` is True on the associated policy.

    Parameters
    ----------
    user_id:
        Unique identifier for this user.
    quota:
        Resource limits for this sandbox.
    enforce_quotas:
        Mirror of the parent policy setting; stored locally for fast access.
    """

    def __init__(
        self,
        user_id: str,
        quota: ResourceQuota,
        enforce_quotas: bool = True,
    ) -> None:
        self._user_id = user_id
        self._quota = quota
        self._enforce_quotas = enforce_quotas
        self._namespace: dict[str, object] = {}
        self._action_timestamps: list[datetime.datetime] = []
        self._cpu_tokens_used: int = 0
        self._active_tools: set[str] = set()
        self._violation_log: list[dict[str, object]] = []

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def user_id(self) -> str:
        """Return the user identifier."""
        return self._user_id

    @property
    def quota(self) -> ResourceQuota:
        """Return the quota attached to this sandbox."""
        return self._quota

    @property
    def cpu_tokens_used(self) -> int:
        """Return how many CPU tokens have been consumed."""
        return self._cpu_tokens_used

    @property
    def active_tool_count(self) -> int:
        """Return the number of currently active tools."""
        return len(self._active_tools)

    # ------------------------------------------------------------------
    # Namespace store
    # ------------------------------------------------------------------

    def set_value(self, key: str, value: object) -> None:
        """Store *value* under *key* in the user's private namespace.

        Parameters
        ----------
        key:
            Namespace key.
        value:
            Arbitrary value to store.

        Raises
        ------
        IsolationViolation
            When the namespace is at capacity and quotas are enforced.
        """
        if (
            self._enforce_quotas
            and key not in self._namespace
            and len(self._namespace) >= self._quota.max_memory_entries
        ):
            raise IsolationViolation(
                self._user_id,
                self._user_id,
                f"Namespace capacity exceeded ({self._quota.max_memory_entries} entries)",
            )
        self._namespace[key] = value

    def get_value(self, key: str, default: object = None) -> object:
        """Return the value stored under *key*, or *default* if absent.

        Parameters
        ----------
        key:
            Namespace key.
        default:
            Fallback value when key is missing.

        Returns
        -------
        object
            The stored value or *default*.
        """
        return self._namespace.get(key, default)

    def delete_value(self, key: str) -> bool:
        """Remove *key* from the namespace.

        Parameters
        ----------
        key:
            Namespace key to remove.

        Returns
        -------
        bool
            True if the key existed and was removed, False otherwise.
        """
        if key in self._namespace:
            del self._namespace[key]
            return True
        return False

    def namespace_keys(self) -> list[str]:
        """Return all keys currently in the namespace (sorted)."""
        return sorted(self._namespace.keys())

    def namespace_size(self) -> int:
        """Return the number of entries in the namespace."""
        return len(self._namespace)

    # ------------------------------------------------------------------
    # Action rate limiting
    # ------------------------------------------------------------------

    def record_action(self, now: datetime.datetime | None = None) -> None:
        """Record that an action occurred at *now* (UTC).

        Parameters
        ----------
        now:
            Override timestamp; defaults to UTC now.

        Raises
        ------
        IsolationViolation
            When the per-minute action rate is exceeded and quotas are enforced.
        """
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)

        # Purge timestamps older than 60 seconds
        cutoff = now - datetime.timedelta(seconds=60)
        self._action_timestamps = [
            ts for ts in self._action_timestamps if ts > cutoff
        ]

        if self._enforce_quotas and len(self._action_timestamps) >= self._quota.max_actions_per_minute:
            raise IsolationViolation(
                self._user_id,
                self._user_id,
                f"Action rate limit exceeded ({self._quota.max_actions_per_minute}/min)",
            )

        self._action_timestamps.append(now)

    def actions_in_last_minute(self, now: datetime.datetime | None = None) -> int:
        """Return the number of actions recorded in the last 60 seconds.

        Parameters
        ----------
        now:
            Reference point for the window; defaults to UTC now.

        Returns
        -------
        int
            Action count within the window.
        """
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(seconds=60)
        return sum(1 for ts in self._action_timestamps if ts > cutoff)

    # ------------------------------------------------------------------
    # CPU token budget
    # ------------------------------------------------------------------

    def consume_tokens(self, amount: int) -> None:
        """Consume *amount* CPU tokens from the budget.

        Parameters
        ----------
        amount:
            Number of tokens to consume (must be >= 0).

        Raises
        ------
        ValueError
            When *amount* is negative.
        IsolationViolation
            When the CPU token budget would be exceeded.
        """
        if amount < 0:
            raise ValueError(f"Token amount must be non-negative, got {amount}")
        if (
            self._enforce_quotas
            and self._cpu_tokens_used + amount > self._quota.max_cpu_tokens
        ):
            raise IsolationViolation(
                self._user_id,
                self._user_id,
                f"CPU token budget exceeded (used={self._cpu_tokens_used}, "
                f"requested={amount}, max={self._quota.max_cpu_tokens})",
            )
        self._cpu_tokens_used += amount

    def remaining_tokens(self) -> int:
        """Return remaining CPU token budget."""
        return max(0, self._quota.max_cpu_tokens - self._cpu_tokens_used)

    # ------------------------------------------------------------------
    # Tool concurrency
    # ------------------------------------------------------------------

    def activate_tool(self, tool_name: str) -> None:
        """Mark *tool_name* as actively running.

        Parameters
        ----------
        tool_name:
            Identifier of the tool being invoked.

        Raises
        ------
        IsolationViolation
            When the concurrent tool limit is reached and quotas are enforced.
        """
        if tool_name in self._active_tools:
            return  # Already active — idempotent
        if (
            self._enforce_quotas
            and len(self._active_tools) >= self._quota.max_concurrent_tools
        ):
            raise IsolationViolation(
                self._user_id,
                self._user_id,
                f"Concurrent tool limit exceeded ({self._quota.max_concurrent_tools})",
            )
        self._active_tools.add(tool_name)

    def deactivate_tool(self, tool_name: str) -> bool:
        """Mark *tool_name* as no longer running.

        Parameters
        ----------
        tool_name:
            Tool to deactivate.

        Returns
        -------
        bool
            True if the tool was active, False otherwise.
        """
        if tool_name in self._active_tools:
            self._active_tools.discard(tool_name)
            return True
        return False

    def active_tools(self) -> list[str]:
        """Return sorted list of currently active tool names."""
        return sorted(self._active_tools)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, object]:
        """Return a summary of current sandbox usage.

        Returns
        -------
        dict[str, object]
            Snapshot of resource usage and limits.
        """
        return {
            "user_id": self._user_id,
            "namespace_size": len(self._namespace),
            "namespace_capacity": self._quota.max_memory_entries,
            "cpu_tokens_used": self._cpu_tokens_used,
            "cpu_tokens_max": self._quota.max_cpu_tokens,
            "active_tool_count": len(self._active_tools),
            "max_concurrent_tools": self._quota.max_concurrent_tools,
            "violation_count": len(self._violation_log),
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class UserSandboxManager:
    """Registry and enforcement layer for all user sandboxes in a session.

    Enforces cross-user access rules defined in the :class:`IsolationPolicy`
    and provides a single entry-point for provisioning user sandboxes.

    Parameters
    ----------
    policy:
        The isolation policy for this session.
    default_quota:
        Default resource quota applied to new sandboxes.
    """

    def __init__(
        self,
        policy: IsolationPolicy,
        default_quota: ResourceQuota | None = None,
    ) -> None:
        self._policy = policy
        self._default_quota = default_quota or ResourceQuota()
        self._sandboxes: dict[str, UserSandbox] = {}
        self._violation_log: list[dict[str, object]] = []

    # ------------------------------------------------------------------
    # Sandbox provisioning
    # ------------------------------------------------------------------

    def create_sandbox(
        self,
        user_id: str,
        quota: ResourceQuota | None = None,
    ) -> UserSandbox:
        """Provision a new sandbox for *user_id*.

        Parameters
        ----------
        user_id:
            Unique user identifier.
        quota:
            Override the default quota for this sandbox.

        Returns
        -------
        UserSandbox
            The newly created sandbox.

        Raises
        ------
        ValueError
            When a sandbox for *user_id* already exists.
        """
        if user_id in self._sandboxes:
            raise ValueError(f"Sandbox already exists for user '{user_id}'")
        sandbox = UserSandbox(
            user_id=user_id,
            quota=quota or self._default_quota,
            enforce_quotas=self._policy.enforce_quotas,
        )
        self._sandboxes[user_id] = sandbox
        return sandbox

    def get_sandbox(self, user_id: str) -> UserSandbox | None:
        """Return the sandbox for *user_id*, or None if not provisioned.

        Parameters
        ----------
        user_id:
            User to look up.

        Returns
        -------
        UserSandbox | None
            The sandbox, or None.
        """
        return self._sandboxes.get(user_id)

    def remove_sandbox(self, user_id: str) -> bool:
        """Remove and destroy the sandbox for *user_id*.

        Parameters
        ----------
        user_id:
            User whose sandbox to remove.

        Returns
        -------
        bool
            True if the sandbox existed and was removed.
        """
        if user_id in self._sandboxes:
            del self._sandboxes[user_id]
            return True
        return False

    def active_users(self) -> list[str]:
        """Return sorted list of users with active sandboxes."""
        return sorted(self._sandboxes.keys())

    def sandbox_count(self) -> int:
        """Return the number of active sandboxes."""
        return len(self._sandboxes)

    # ------------------------------------------------------------------
    # Cross-user access
    # ------------------------------------------------------------------

    def read_cross_user(
        self, requesting_user_id: str, target_user_id: str, key: str
    ) -> object:
        """Read a value from another user's namespace.

        Parameters
        ----------
        requesting_user_id:
            The user making the cross-user read request.
        target_user_id:
            The user whose namespace is being read.
        key:
            Namespace key to read.

        Returns
        -------
        object
            The value stored under *key* in the target's namespace,
            or None if absent.

        Raises
        ------
        IsolationViolation
            When cross-user reads are not permitted by policy.
        ValueError
            When either user's sandbox does not exist.
        """
        self._require_sandbox(requesting_user_id)
        self._require_sandbox(target_user_id)

        if not self._policy.allows_cross_read(key):
            violation = IsolationViolation(
                requesting_user_id,
                target_user_id,
                f"Cross-user read denied for key '{key}' under policy "
                f"'{self._policy.cross_user_access.value}'",
            )
            self._log_violation(violation)
            raise violation

        return self._sandboxes[target_user_id].get_value(key)

    def write_cross_user(
        self,
        requesting_user_id: str,
        target_user_id: str,
        key: str,
        value: object,
    ) -> None:
        """Write a value into another user's namespace.

        Parameters
        ----------
        requesting_user_id:
            The user requesting the write.
        target_user_id:
            The user whose namespace will be written.
        key:
            Namespace key to write.
        value:
            Value to store.

        Raises
        ------
        IsolationViolation
            When cross-user writes are not permitted by policy.
        ValueError
            When either user's sandbox does not exist.
        """
        self._require_sandbox(requesting_user_id)
        self._require_sandbox(target_user_id)

        if not self._policy.allows_cross_write():
            violation = IsolationViolation(
                requesting_user_id,
                target_user_id,
                f"Cross-user write denied under policy "
                f"'{self._policy.cross_user_access.value}'",
            )
            self._log_violation(violation)
            raise violation

        self._sandboxes[target_user_id].set_value(key, value)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def session_stats(self) -> dict[str, object]:
        """Return an aggregate summary of all sandboxes.

        Returns
        -------
        dict[str, object]
            Session-level resource usage summary.
        """
        return {
            "session_id": self._policy.session_id,
            "active_users": len(self._sandboxes),
            "cross_user_access": self._policy.cross_user_access.value,
            "enforce_quotas": self._policy.enforce_quotas,
            "violation_count": len(self._violation_log),
            "user_stats": {
                uid: sandbox.stats()
                for uid, sandbox in self._sandboxes.items()
            },
        }

    def violation_count(self) -> int:
        """Return the total number of logged isolation violations."""
        return len(self._violation_log)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_sandbox(self, user_id: str) -> None:
        if user_id not in self._sandboxes:
            raise ValueError(f"No sandbox found for user '{user_id}'")

    def _log_violation(self, violation: IsolationViolation) -> None:
        if self._policy.audit_violations:
            self._violation_log.append({
                "user_id": violation.user_id,
                "target_user_id": violation.target_user_id,
                "reason": violation.reason,
                "logged_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })


__all__ = [
    "CrossUserAccess",
    "IsolationPolicy",
    "IsolationViolation",
    "ResourceQuota",
    "UserSandbox",
    "UserSandboxManager",
]
