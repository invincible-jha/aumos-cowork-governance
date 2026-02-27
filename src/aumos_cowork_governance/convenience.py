"""Convenience API for aumos-cowork-governance — 3-line quickstart.

Example
-------
::

    from aumos_cowork_governance import CoworkGovernor
    governor = CoworkGovernor()
    result = governor.evaluate({"action": "file_read", "path": "/data.csv"})
    print(result.allowed)

"""
from __future__ import annotations

from typing import Any


class CoworkGovernor:
    """Zero-config multi-agent collaboration governance for the 80% use case.

    Wraps PolicyEngine with sensible defaults. No policy file is required;
    an empty permissive policy is used when none is provided.

    Parameters
    ----------
    policy:
        Optional pre-built policy dict. If None, an empty policy (all
        actions allowed) is loaded from the engine's defaults.

    Example
    -------
    ::

        from aumos_cowork_governance import CoworkGovernor
        governor = CoworkGovernor()
        result = governor.evaluate({"action": "message", "content": "Hello!"})
        print(result.allowed)  # True
    """

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        from aumos_cowork_governance.policies.engine import PolicyEngine

        self._engine = PolicyEngine()
        effective_policy = policy if policy is not None else {"policies": []}
        self._engine.load_from_dict(effective_policy)

    def evaluate(self, action: dict[str, Any]) -> Any:
        """Evaluate an agent action against the governance policy.

        Parameters
        ----------
        action:
            Dict describing the agent action to evaluate. Common keys:
            ``action`` (action type), ``agent_id``, and action-specific fields.

        Returns
        -------
        EvaluationResult
            Result with ``.allowed`` bool and ``.violations`` list.

        Example
        -------
        ::

            governor = CoworkGovernor()
            result = governor.evaluate({"action": "send_message", "content": "hello"})
            assert result.allowed
        """
        return self._engine.evaluate(action)

    @property
    def engine(self) -> Any:
        """The underlying PolicyEngine instance."""
        return self._engine

    def __repr__(self) -> str:
        return "CoworkGovernor(engine=PolicyEngine)"
