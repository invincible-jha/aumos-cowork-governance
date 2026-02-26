"""Cowork agent lifecycle hooks.

CoworkHooks is a callable container that can be registered with a Cowork
agent to intercept file access, API calls, and file write operations.

Each hook method receives an action context dict and returns a (possibly
modified) context dict.  Hooks run synchronously in the agent's call stack.

Example
-------
>>> plugin = GovernancePlugin()
>>> plugin.load_config(Path("governance.yaml"))
>>> hooks = CoworkHooks(plugin)
>>> # Register hooks with the Cowork agent (pseudo-code):
>>> agent.on("pre_file_access", hooks.pre_file_access)
>>> agent.on("post_file_access", hooks.post_file_access)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aumos_cowork_governance.plugin.governance_plugin import GovernancePlugin

logger = logging.getLogger(__name__)


class CoworkHooks:
    """Lifecycle hooks for the Cowork agent integration.

    Each method corresponds to a Cowork agent event and wraps the
    :class:`GovernancePlugin` pre/post action lifecycle.

    Parameters
    ----------
    plugin:
        The initialised :class:`GovernancePlugin` instance.
    """

    def __init__(self, plugin: "GovernancePlugin") -> None:
        self._plugin = plugin

    # ------------------------------------------------------------------
    # File access hooks
    # ------------------------------------------------------------------

    def pre_file_access(
        self,
        context: dict[str, object],
    ) -> dict[str, object]:
        """Called before the agent reads a file.

        Injects ``action="file_read"`` and evaluates all policies.

        Parameters
        ----------
        context:
            Must include ``path`` (str).  May include ``agent``,
            ``task_id``, ``sensitivity``.

        Returns
        -------
        dict[str, object]
            Governance evaluation result.  If ``allowed=False`` callers
            should abort the file access.
        """
        ctx = {"action": "file_read", **context}
        return self._plugin.pre_action(ctx)

    def post_file_access(
        self,
        context: dict[str, object],
        result: dict[str, object],
    ) -> None:
        """Called after the agent reads a file.

        Parameters
        ----------
        context:
            The original pre-access context.
        result:
            The file read result (may include ``content``, ``size_bytes``).
        """
        ctx = {"action": "file_read", **context}
        self._plugin.post_action(ctx, result)

    # ------------------------------------------------------------------
    # File write hooks
    # ------------------------------------------------------------------

    def pre_file_write(
        self,
        context: dict[str, object],
    ) -> dict[str, object]:
        """Called before the agent writes a file.

        Parameters
        ----------
        context:
            Must include ``path`` (str).  May include ``content``,
            ``agent``, ``task_id``, ``sensitivity``.

        Returns
        -------
        dict[str, object]
            Governance evaluation result.
        """
        ctx = {"action": "file_write", **context}
        return self._plugin.pre_action(ctx)

    def post_file_write(
        self,
        context: dict[str, object],
        result: dict[str, object],
    ) -> None:
        """Called after the agent writes a file.

        Parameters
        ----------
        context:
            The original pre-write context.
        result:
            The write result (may include ``bytes_written``, ``path``).
        """
        ctx = {"action": "file_write", **context}
        self._plugin.post_action(ctx, result)

    # ------------------------------------------------------------------
    # API call hooks
    # ------------------------------------------------------------------

    def pre_api_call(
        self,
        context: dict[str, object],
    ) -> dict[str, object]:
        """Called before the agent makes an external API call.

        Parameters
        ----------
        context:
            Must include ``url`` (str).  May include ``method``,
            ``estimated_cost_usd``, ``total_tokens``, ``daily_cost_usd``,
            ``agent``, ``task_id``.

        Returns
        -------
        dict[str, object]
            Governance evaluation result.
        """
        ctx = {"action": "api_call", **context}
        return self._plugin.pre_action(ctx)

    def post_api_call(
        self,
        context: dict[str, object],
        result: dict[str, object],
    ) -> None:
        """Called after the agent completes an external API call.

        Parameters
        ----------
        context:
            The original pre-call context.
        result:
            The API result dict.  May include ``cost_usd``,
            ``input_tokens``, ``output_tokens``, ``model``,
            ``status_code``.
        """
        ctx = {"action": "api_call", **context}
        self._plugin.post_action(ctx, result)
