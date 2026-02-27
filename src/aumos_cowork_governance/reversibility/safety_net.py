"""Reversibility safety net for agent co-work sessions.

Captures a snapshot of agent-accessible state before any destructive action
and provides a stack-based undo mechanism.  This allows governance systems
to offer "undo last N actions" functionality.

Key classes
-----------
PreActionSnapshot : Frozen capture of state before an action.
UndoManager       : Stack-based manager for snapshots with undo support.
ActionReversibility : Enum classifying whether an action can be undone.
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ActionReversibility(str, Enum):
    """Classification of action reversibility."""

    REVERSIBLE = "reversible"          # Can be undone via snapshot restore
    PARTIALLY_REVERSIBLE = "partially_reversible"  # Can be partially undone
    IRREVERSIBLE = "irreversible"      # Cannot be undone (e.g. email sent)
    UNKNOWN = "unknown"                # Reversibility not determined


# ---------------------------------------------------------------------------
# Pre-action snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreActionSnapshot:
    """Immutable snapshot of state captured before a destructive action.

    Attributes
    ----------
    snapshot_id:
        Unique identifier for this snapshot.
    action_type:
        Human-readable label for the action about to be taken.
    state_before:
        Deep copy of the state to restore on undo.
    captured_at:
        UTC timestamp when the snapshot was taken.
    reversibility:
        Whether this action can be undone.
    metadata:
        Optional context (e.g. user_id, session_id).
    state_checksum:
        SHA-256 of the serialised state for integrity verification.
    """

    snapshot_id: str
    action_type: str
    state_before: object
    captured_at: datetime.datetime
    reversibility: ActionReversibility
    metadata: dict[str, object]
    state_checksum: str

    def verify_integrity(self) -> bool:
        """Verify that the stored state matches the recorded checksum.

        Returns
        -------
        bool
            True when the computed checksum matches :attr:`state_checksum`.
        """
        try:
            serialised = json.dumps(self.state_before, sort_keys=True, default=str)
            computed = hashlib.sha256(serialised.encode("utf-8")).hexdigest()
            return computed == self.state_checksum
        except (TypeError, ValueError):
            return False


# ---------------------------------------------------------------------------
# Undo manager
# ---------------------------------------------------------------------------


class UndoManager:
    """Stack-based manager for pre-action snapshots.

    Provides capture-before-action, undo, and redo (undo undo) semantics.

    Parameters
    ----------
    max_stack_size:
        Maximum number of snapshots retained.  Oldest snapshots are dropped
        when the stack exceeds this limit (default: 50).

    Example
    -------
    ::

        manager = UndoManager()
        state = {"text": "original"}
        snapshot = manager.capture("edit_text", state)
        state["text"] = "modified"
        state = manager.undo()  # → {"text": "original"}
    """

    def __init__(self, max_stack_size: int = 50) -> None:
        self._max_stack_size = max_stack_size
        self._undo_stack: list[PreActionSnapshot] = []
        self._redo_stack: list[PreActionSnapshot] = []
        self._action_registry: dict[str, ActionReversibility] = {}
        self._restore_callbacks: list[Callable[[PreActionSnapshot], None]] = []
        self._counter: int = 0

    # ------------------------------------------------------------------
    # Action registry
    # ------------------------------------------------------------------

    def register_action(
        self, action_type: str, reversibility: ActionReversibility
    ) -> None:
        """Register the reversibility classification for an action type.

        Parameters
        ----------
        action_type:
            The action type label.
        reversibility:
            How this action type can be undone.
        """
        self._action_registry[action_type] = reversibility

    # ------------------------------------------------------------------
    # Capture
    # ------------------------------------------------------------------

    def capture(
        self,
        action_type: str,
        state: object,
        metadata: dict[str, object] | None = None,
        reversibility: ActionReversibility | None = None,
    ) -> PreActionSnapshot:
        """Capture a snapshot of *state* before an action executes.

        Parameters
        ----------
        action_type:
            Label describing the pending action.
        state:
            The current state to snapshot (deep-copied).
        metadata:
            Optional context dict.
        reversibility:
            Override the registered reversibility for this action.

        Returns
        -------
        PreActionSnapshot
            The captured (immutable) snapshot.
        """
        self._counter += 1
        snapshot_id = f"snap-{self._counter:06d}"
        state_copy = copy.deepcopy(state)

        try:
            serialised = json.dumps(state_copy, sort_keys=True, default=str)
            checksum = hashlib.sha256(serialised.encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            checksum = ""

        rev = reversibility or self._action_registry.get(
            action_type, ActionReversibility.UNKNOWN
        )

        snapshot = PreActionSnapshot(
            snapshot_id=snapshot_id,
            action_type=action_type,
            state_before=state_copy,
            captured_at=datetime.datetime.now(datetime.timezone.utc),
            reversibility=rev,
            metadata=dict(metadata or {}),
            state_checksum=checksum,
        )

        self._undo_stack.append(snapshot)
        self._redo_stack.clear()  # New action clears redo stack

        # Enforce max stack size
        while len(self._undo_stack) > self._max_stack_size:
            self._undo_stack.pop(0)

        return snapshot

    # ------------------------------------------------------------------
    # Undo / redo
    # ------------------------------------------------------------------

    def undo(self) -> object | None:
        """Pop the most recent snapshot and restore its state.

        The popped snapshot is pushed onto the redo stack.

        Returns
        -------
        Any | None
            The restored state, or None if the undo stack is empty.
        """
        if not self._undo_stack:
            return None

        snapshot = self._undo_stack.pop()
        self._redo_stack.append(snapshot)

        restored_state = copy.deepcopy(snapshot.state_before)

        for callback in self._restore_callbacks:
            try:
                callback(snapshot, restored_state)
            except Exception:
                pass  # Callbacks must not disrupt undo

        return restored_state

    def redo(self) -> object | None:
        """Re-apply the most recently undone action.

        Pops from the redo stack and pushes back onto the undo stack.
        Note: this restores the *pre-undo* snapshot (i.e. the state after
        the original action), not the state before redo.

        Returns
        -------
        Any | None
            The state from before the undo was applied, or None if redo
            stack is empty.
        """
        if not self._redo_stack:
            return None

        snapshot = self._redo_stack.pop()
        self._undo_stack.append(snapshot)
        # Return the state *after* the original action — we cannot easily
        # reconstruct it without the action result, so we return the snapshot
        # itself for caller inspection.
        return copy.deepcopy(snapshot.state_before)

    def can_undo(self) -> bool:
        """Return True if there are snapshots available to undo."""
        return len(self._undo_stack) > 0

    def can_redo(self) -> bool:
        """Return True if there are snapshots on the redo stack."""
        return len(self._redo_stack) > 0

    # ------------------------------------------------------------------
    # Stack introspection
    # ------------------------------------------------------------------

    def undo_stack_size(self) -> int:
        """Return the number of snapshots on the undo stack."""
        return len(self._undo_stack)

    def redo_stack_size(self) -> int:
        """Return the number of snapshots on the redo stack."""
        return len(self._redo_stack)

    def peek_undo(self) -> PreActionSnapshot | None:
        """Return the most recent undo snapshot without popping it."""
        return self._undo_stack[-1] if self._undo_stack else None

    def clear(self) -> None:
        """Clear both undo and redo stacks."""
        self._undo_stack.clear()
        self._redo_stack.clear()

    def get_undo_history(self) -> list[PreActionSnapshot]:
        """Return all snapshots on the undo stack (oldest first)."""
        return list(self._undo_stack)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def on_restore(
        self, callback: Callable[[PreActionSnapshot], None]
    ) -> None:
        """Register a callback called when undo restores a snapshot.

        Parameters
        ----------
        callback:
            Called as ``callback(snapshot, restored_state)`` after each
            successful undo operation.
        """
        self._restore_callbacks.append(callback)

    # ------------------------------------------------------------------
    # Reversibility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_reversible(snapshot: PreActionSnapshot) -> bool:
        """Return True if *snapshot* represents a reversible action.

        Parameters
        ----------
        snapshot:
            The snapshot to check.

        Returns
        -------
        bool
            True for REVERSIBLE or PARTIALLY_REVERSIBLE.
        """
        return snapshot.reversibility in (
            ActionReversibility.REVERSIBLE,
            ActionReversibility.PARTIALLY_REVERSIBLE,
        )


__all__ = [
    "ActionReversibility",
    "PreActionSnapshot",
    "UndoManager",
]
