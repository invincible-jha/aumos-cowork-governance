"""Tests for aumos_cowork_governance.isolation.sandbox."""
from __future__ import annotations

import datetime

import pytest

from aumos_cowork_governance.isolation.sandbox import (
    CrossUserAccess,
    IsolationPolicy,
    IsolationViolation,
    ResourceQuota,
    UserSandbox,
    UserSandboxManager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def quota() -> ResourceQuota:
    return ResourceQuota(
        max_actions_per_minute=10,
        max_memory_entries=5,
        max_cpu_tokens=100,
        max_concurrent_tools=2,
    )


@pytest.fixture()
def deny_policy() -> IsolationPolicy:
    return IsolationPolicy(
        session_id="sess-1",
        cross_user_access=CrossUserAccess.DENY_ALL,
        enforce_quotas=True,
    )


@pytest.fixture()
def read_policy() -> IsolationPolicy:
    return IsolationPolicy(
        session_id="sess-1",
        cross_user_access=CrossUserAccess.READ_ONLY,
        enforce_quotas=True,
    )


@pytest.fixture()
def allow_policy() -> IsolationPolicy:
    return IsolationPolicy(
        session_id="sess-1",
        cross_user_access=CrossUserAccess.ALLOW_ALL,
        enforce_quotas=True,
    )


@pytest.fixture()
def sandbox(quota: ResourceQuota) -> UserSandbox:
    return UserSandbox(user_id="u-1", quota=quota, enforce_quotas=True)


@pytest.fixture()
def manager(deny_policy: IsolationPolicy, quota: ResourceQuota) -> UserSandboxManager:
    mgr = UserSandboxManager(policy=deny_policy, default_quota=quota)
    mgr.create_sandbox("u-1")
    mgr.create_sandbox("u-2")
    return mgr


# ---------------------------------------------------------------------------
# ResourceQuota
# ---------------------------------------------------------------------------


class TestResourceQuota:
    def test_default_values(self) -> None:
        quota = ResourceQuota()
        assert quota.max_actions_per_minute == 60
        assert quota.max_memory_entries == 1_000
        assert quota.max_cpu_tokens == 10_000
        assert quota.max_concurrent_tools == 5

    def test_frozen(self) -> None:
        quota = ResourceQuota()
        with pytest.raises((AttributeError, TypeError)):
            quota.max_actions_per_minute = 999  # type: ignore[misc]


# ---------------------------------------------------------------------------
# IsolationPolicy
# ---------------------------------------------------------------------------


class TestIsolationPolicy:
    def test_deny_all_blocks_reads(self, deny_policy: IsolationPolicy) -> None:
        assert deny_policy.allows_cross_read("any_key") is False

    def test_deny_all_blocks_writes(self, deny_policy: IsolationPolicy) -> None:
        assert deny_policy.allows_cross_write() is False

    def test_read_only_allows_reads(self, read_policy: IsolationPolicy) -> None:
        assert read_policy.allows_cross_read("any_key") is True

    def test_read_only_blocks_writes(self, read_policy: IsolationPolicy) -> None:
        assert read_policy.allows_cross_write() is False

    def test_allow_all_permits_reads(self, allow_policy: IsolationPolicy) -> None:
        assert allow_policy.allows_cross_read("any_key") is True

    def test_allow_all_permits_writes(self, allow_policy: IsolationPolicy) -> None:
        assert allow_policy.allows_cross_write() is True

    def test_shared_namespace_readable_in_deny_mode(self) -> None:
        policy = IsolationPolicy(
            session_id="s-1",
            cross_user_access=CrossUserAccess.DENY_ALL,
            allow_shared_read_namespaces=frozenset({"public_key"}),
        )
        assert policy.allows_cross_read("public_key") is True
        assert policy.allows_cross_read("private_key") is False

    def test_policy_is_frozen(self, deny_policy: IsolationPolicy) -> None:
        with pytest.raises((AttributeError, TypeError)):
            deny_policy.session_id = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# UserSandbox — namespace
# ---------------------------------------------------------------------------


class TestUserSandboxNamespace:
    def test_set_and_get_value(self, sandbox: UserSandbox) -> None:
        sandbox.set_value("key", "value")
        assert sandbox.get_value("key") == "value"

    def test_get_missing_key_returns_default(self, sandbox: UserSandbox) -> None:
        assert sandbox.get_value("missing") is None
        assert sandbox.get_value("missing", "fallback") == "fallback"

    def test_delete_existing_key(self, sandbox: UserSandbox) -> None:
        sandbox.set_value("k", "v")
        result = sandbox.delete_value("k")
        assert result is True
        assert sandbox.get_value("k") is None

    def test_delete_missing_key(self, sandbox: UserSandbox) -> None:
        assert sandbox.delete_value("no_such_key") is False

    def test_namespace_keys_sorted(self, sandbox: UserSandbox) -> None:
        sandbox.set_value("z_key", 1)
        sandbox.set_value("a_key", 2)
        assert sandbox.namespace_keys() == ["a_key", "z_key"]

    def test_namespace_size(self, sandbox: UserSandbox) -> None:
        assert sandbox.namespace_size() == 0
        sandbox.set_value("k1", 1)
        sandbox.set_value("k2", 2)
        assert sandbox.namespace_size() == 2

    def test_namespace_capacity_enforced(self, sandbox: UserSandbox) -> None:
        # quota.max_memory_entries = 5
        for i in range(5):
            sandbox.set_value(f"k{i}", i)
        with pytest.raises(IsolationViolation):
            sandbox.set_value("overflow", "boom")

    def test_overwrite_does_not_count_as_new_entry(self, sandbox: UserSandbox) -> None:
        for i in range(5):
            sandbox.set_value(f"k{i}", i)
        # Overwriting an existing key should not raise
        sandbox.set_value("k0", "updated")
        assert sandbox.get_value("k0") == "updated"


# ---------------------------------------------------------------------------
# UserSandbox — action rate limiting
# ---------------------------------------------------------------------------


class TestUserSandboxActions:
    def test_record_action_increments_count(self, sandbox: UserSandbox) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        sandbox.record_action(now)
        assert sandbox.actions_in_last_minute(now) == 1

    def test_old_actions_not_counted(self, sandbox: UserSandbox) -> None:
        old = datetime.datetime(2020, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        sandbox.record_action(old)
        now = datetime.datetime.now(datetime.timezone.utc)
        assert sandbox.actions_in_last_minute(now) == 0

    def test_rate_limit_enforced(self, sandbox: UserSandbox) -> None:
        # quota.max_actions_per_minute = 10
        now = datetime.datetime.now(datetime.timezone.utc)
        for _ in range(10):
            sandbox.record_action(now)
        with pytest.raises(IsolationViolation):
            sandbox.record_action(now)


# ---------------------------------------------------------------------------
# UserSandbox — CPU tokens
# ---------------------------------------------------------------------------


class TestUserSandboxTokens:
    def test_consume_tokens(self, sandbox: UserSandbox) -> None:
        sandbox.consume_tokens(30)
        assert sandbox.cpu_tokens_used == 30
        assert sandbox.remaining_tokens() == 70

    def test_token_budget_enforced(self, sandbox: UserSandbox) -> None:
        # quota.max_cpu_tokens = 100
        sandbox.consume_tokens(90)
        with pytest.raises(IsolationViolation):
            sandbox.consume_tokens(20)

    def test_negative_tokens_raises(self, sandbox: UserSandbox) -> None:
        with pytest.raises(ValueError):
            sandbox.consume_tokens(-1)

    def test_zero_tokens_allowed(self, sandbox: UserSandbox) -> None:
        sandbox.consume_tokens(0)
        assert sandbox.cpu_tokens_used == 0


# ---------------------------------------------------------------------------
# UserSandbox — tool concurrency
# ---------------------------------------------------------------------------


class TestUserSandboxTools:
    def test_activate_tool(self, sandbox: UserSandbox) -> None:
        sandbox.activate_tool("tool_a")
        assert "tool_a" in sandbox.active_tools()

    def test_activate_same_tool_idempotent(self, sandbox: UserSandbox) -> None:
        sandbox.activate_tool("tool_a")
        sandbox.activate_tool("tool_a")
        assert sandbox.active_tool_count == 1

    def test_deactivate_tool(self, sandbox: UserSandbox) -> None:
        sandbox.activate_tool("tool_a")
        result = sandbox.deactivate_tool("tool_a")
        assert result is True
        assert sandbox.active_tool_count == 0

    def test_deactivate_missing_tool(self, sandbox: UserSandbox) -> None:
        assert sandbox.deactivate_tool("no_such") is False

    def test_concurrent_tool_limit_enforced(self, sandbox: UserSandbox) -> None:
        # quota.max_concurrent_tools = 2
        sandbox.activate_tool("tool_a")
        sandbox.activate_tool("tool_b")
        with pytest.raises(IsolationViolation):
            sandbox.activate_tool("tool_c")

    def test_active_tools_sorted(self, sandbox: UserSandbox) -> None:
        sandbox.activate_tool("z_tool")
        sandbox.activate_tool("a_tool")
        assert sandbox.active_tools() == ["a_tool", "z_tool"]


# ---------------------------------------------------------------------------
# UserSandboxManager — provisioning
# ---------------------------------------------------------------------------


class TestUserSandboxManagerProvisioning:
    def test_create_sandbox(self, deny_policy: IsolationPolicy) -> None:
        mgr = UserSandboxManager(policy=deny_policy)
        sb = mgr.create_sandbox("u-1")
        assert isinstance(sb, UserSandbox)
        assert sb.user_id == "u-1"

    def test_duplicate_sandbox_raises(self, deny_policy: IsolationPolicy) -> None:
        mgr = UserSandboxManager(policy=deny_policy)
        mgr.create_sandbox("u-1")
        with pytest.raises(ValueError):
            mgr.create_sandbox("u-1")

    def test_get_sandbox(self, manager: UserSandboxManager) -> None:
        sb = manager.get_sandbox("u-1")
        assert sb is not None
        assert sb.user_id == "u-1"

    def test_get_missing_sandbox(self, manager: UserSandboxManager) -> None:
        assert manager.get_sandbox("no-such") is None

    def test_remove_sandbox(self, manager: UserSandboxManager) -> None:
        result = manager.remove_sandbox("u-1")
        assert result is True
        assert manager.get_sandbox("u-1") is None

    def test_remove_missing_sandbox(self, manager: UserSandboxManager) -> None:
        assert manager.remove_sandbox("ghost") is False

    def test_active_users_sorted(self, manager: UserSandboxManager) -> None:
        assert manager.active_users() == ["u-1", "u-2"]

    def test_sandbox_count(self, manager: UserSandboxManager) -> None:
        assert manager.sandbox_count() == 2


# ---------------------------------------------------------------------------
# UserSandboxManager — cross-user access
# ---------------------------------------------------------------------------


class TestCrossUserAccess:
    def test_deny_policy_blocks_cross_read(self, manager: UserSandboxManager) -> None:
        manager.get_sandbox("u-1").set_value("secret", "data")  # type: ignore[union-attr]
        with pytest.raises(IsolationViolation):
            manager.read_cross_user("u-2", "u-1", "secret")

    def test_deny_policy_blocks_cross_write(self, manager: UserSandboxManager) -> None:
        with pytest.raises(IsolationViolation):
            manager.write_cross_user("u-2", "u-1", "key", "value")

    def test_read_policy_allows_cross_read(
        self, read_policy: IsolationPolicy, quota: ResourceQuota
    ) -> None:
        mgr = UserSandboxManager(policy=read_policy, default_quota=quota)
        mgr.create_sandbox("u-1")
        mgr.create_sandbox("u-2")
        mgr.get_sandbox("u-1").set_value("data", 42)  # type: ignore[union-attr]
        result = mgr.read_cross_user("u-2", "u-1", "data")
        assert result == 42

    def test_read_policy_blocks_cross_write(
        self, read_policy: IsolationPolicy, quota: ResourceQuota
    ) -> None:
        mgr = UserSandboxManager(policy=read_policy, default_quota=quota)
        mgr.create_sandbox("u-1")
        mgr.create_sandbox("u-2")
        with pytest.raises(IsolationViolation):
            mgr.write_cross_user("u-2", "u-1", "key", "value")

    def test_allow_policy_permits_cross_write(
        self, allow_policy: IsolationPolicy, quota: ResourceQuota
    ) -> None:
        mgr = UserSandboxManager(policy=allow_policy, default_quota=quota)
        mgr.create_sandbox("u-1")
        mgr.create_sandbox("u-2")
        mgr.write_cross_user("u-2", "u-1", "shared", "hello")
        assert mgr.get_sandbox("u-1").get_value("shared") == "hello"  # type: ignore[union-attr]

    def test_cross_read_missing_sandbox_raises(self, manager: UserSandboxManager) -> None:
        with pytest.raises(ValueError):
            manager.read_cross_user("u-1", "ghost", "key")

    def test_violation_count_increments(self, manager: UserSandboxManager) -> None:
        assert manager.violation_count() == 0
        try:
            manager.read_cross_user("u-2", "u-1", "key")
        except IsolationViolation:
            pass
        assert manager.violation_count() == 1

    def test_session_stats_structure(self, manager: UserSandboxManager) -> None:
        stats = manager.session_stats()
        assert stats["session_id"] == "sess-1"
        assert stats["active_users"] == 2
        assert "u-1" in stats["user_stats"]
        assert "u-2" in stats["user_stats"]
