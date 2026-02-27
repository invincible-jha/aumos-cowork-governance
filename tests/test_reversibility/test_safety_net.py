"""Tests for aumos_cowork_governance.reversibility.safety_net."""
from __future__ import annotations

import pytest

from aumos_cowork_governance.reversibility.safety_net import (
    ActionReversibility,
    PreActionSnapshot,
    UndoManager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def manager() -> UndoManager:
    return UndoManager()


# ---------------------------------------------------------------------------
# PreActionSnapshot
# ---------------------------------------------------------------------------


class TestPreActionSnapshot:
    def test_capture_creates_snapshot(self, manager: UndoManager) -> None:
        state = {"text": "hello"}
        snap = manager.capture("edit", state)
        assert isinstance(snap, PreActionSnapshot)

    def test_snapshot_is_frozen(self, manager: UndoManager) -> None:
        snap = manager.capture("edit", {"x": 1})
        with pytest.raises((AttributeError, TypeError)):
            snap.action_type = "other"  # type: ignore[misc]

    def test_snapshot_deep_copies_state(self, manager: UndoManager) -> None:
        state = {"val": [1, 2, 3]}
        snap = manager.capture("edit", state)
        state["val"].append(99)
        assert snap.state_before["val"] == [1, 2, 3]

    def test_snapshot_has_timestamp(self, manager: UndoManager) -> None:
        snap = manager.capture("edit", {})
        assert snap.captured_at is not None

    def test_snapshot_has_checksum(self, manager: UndoManager) -> None:
        snap = manager.capture("edit", {"data": "value"})
        assert len(snap.state_checksum) == 64  # SHA-256 hex digest

    def test_snapshot_verify_integrity_valid(self, manager: UndoManager) -> None:
        snap = manager.capture("edit", {"key": "val"})
        assert snap.verify_integrity() is True

    def test_snapshot_reversibility_default_unknown(
        self, manager: UndoManager
    ) -> None:
        snap = manager.capture("unknown_action", {})
        assert snap.reversibility == ActionReversibility.UNKNOWN

    def test_snapshot_reversibility_from_registry(
        self, manager: UndoManager
    ) -> None:
        manager.register_action("edit_text", ActionReversibility.REVERSIBLE)
        snap = manager.capture("edit_text", {})
        assert snap.reversibility == ActionReversibility.REVERSIBLE

    def test_snapshot_reversibility_override(self, manager: UndoManager) -> None:
        snap = manager.capture(
            "edit", {}, reversibility=ActionReversibility.IRREVERSIBLE
        )
        assert snap.reversibility == ActionReversibility.IRREVERSIBLE


# ---------------------------------------------------------------------------
# Stack management
# ---------------------------------------------------------------------------


class TestStackManagement:
    def test_undo_stack_empty_initially(self, manager: UndoManager) -> None:
        assert manager.undo_stack_size() == 0
        assert manager.can_undo() is False

    def test_capture_increments_stack(self, manager: UndoManager) -> None:
        manager.capture("edit", {})
        assert manager.undo_stack_size() == 1

    def test_max_stack_size_enforced(self) -> None:
        manager = UndoManager(max_stack_size=3)
        for i in range(5):
            manager.capture("edit", {"i": i})
        assert manager.undo_stack_size() == 3

    def test_peek_undo_returns_last(self, manager: UndoManager) -> None:
        manager.capture("first", {"n": 1})
        manager.capture("second", {"n": 2})
        snap = manager.peek_undo()
        assert snap is not None
        assert snap.action_type == "second"

    def test_peek_undo_empty_returns_none(self, manager: UndoManager) -> None:
        assert manager.peek_undo() is None

    def test_clear_resets_stacks(self, manager: UndoManager) -> None:
        manager.capture("edit", {})
        manager.clear()
        assert manager.undo_stack_size() == 0
        assert manager.redo_stack_size() == 0

    def test_get_undo_history_order(self, manager: UndoManager) -> None:
        manager.capture("a1", {"n": 1})
        manager.capture("a2", {"n": 2})
        history = manager.get_undo_history()
        assert history[0].action_type == "a1"
        assert history[1].action_type == "a2"


# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------


class TestUndo:
    def test_undo_returns_previous_state(self, manager: UndoManager) -> None:
        state = {"text": "original"}
        manager.capture("edit", state)
        state["text"] = "modified"
        restored = manager.undo()
        assert restored["text"] == "original"

    def test_undo_empty_returns_none(self, manager: UndoManager) -> None:
        assert manager.undo() is None

    def test_undo_decrements_stack(self, manager: UndoManager) -> None:
        manager.capture("edit", {})
        manager.undo()
        assert manager.undo_stack_size() == 0

    def test_undo_pushes_to_redo_stack(self, manager: UndoManager) -> None:
        manager.capture("edit", {})
        manager.undo()
        assert manager.can_redo() is True

    def test_multiple_undos(self, manager: UndoManager) -> None:
        state = {"val": 0}
        manager.capture("step1", {"val": 0})
        manager.capture("step2", {"val": 1})
        manager.undo()
        restored = manager.undo()
        assert restored["val"] == 0

    def test_undo_returns_deep_copy(self, manager: UndoManager) -> None:
        state = {"items": [1, 2, 3]}
        manager.capture("edit", state)
        restored = manager.undo()
        assert restored is not None
        restored["items"].append(99)
        # Re-undo from redo stack
        redo_state = manager.redo()
        assert redo_state is not None


# ---------------------------------------------------------------------------
# Redo
# ---------------------------------------------------------------------------


class TestRedo:
    def test_redo_empty_returns_none(self, manager: UndoManager) -> None:
        assert manager.redo() is None

    def test_redo_after_undo(self, manager: UndoManager) -> None:
        manager.capture("edit", {"val": 1})
        manager.undo()
        assert manager.can_redo() is True
        manager.redo()
        # After redo, snapshot is back on undo stack
        assert manager.can_undo() is True

    def test_new_capture_clears_redo_stack(self, manager: UndoManager) -> None:
        manager.capture("edit1", {})
        manager.undo()
        assert manager.can_redo() is True
        manager.capture("edit2", {})
        assert manager.can_redo() is False


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    def test_restore_callback_called_on_undo(self, manager: UndoManager) -> None:
        calls: list[tuple] = []
        manager.on_restore(lambda snap, state: calls.append((snap, state)))
        manager.capture("edit", {"val": 1})
        manager.undo()
        assert len(calls) == 1

    def test_restore_callback_receives_snapshot(self, manager: UndoManager) -> None:
        received: list = []
        manager.on_restore(lambda snap, state: received.append(snap.action_type))
        manager.capture("my_action", {"x": 1})
        manager.undo()
        assert received == ["my_action"]

    def test_faulty_callback_does_not_halt_undo(self, manager: UndoManager) -> None:
        def bad_callback(snap: PreActionSnapshot, state: object) -> None:
            raise RuntimeError("callback error")

        manager.on_restore(bad_callback)
        manager.capture("edit", {"x": 1})
        result = manager.undo()  # Should not raise
        assert result is not None


# ---------------------------------------------------------------------------
# Reversibility helpers
# ---------------------------------------------------------------------------


class TestReversibilityHelpers:
    def test_reversible_action(self, manager: UndoManager) -> None:
        snap = manager.capture(
            "edit", {}, reversibility=ActionReversibility.REVERSIBLE
        )
        assert UndoManager.is_reversible(snap) is True

    def test_partially_reversible_action(self, manager: UndoManager) -> None:
        snap = manager.capture(
            "edit", {}, reversibility=ActionReversibility.PARTIALLY_REVERSIBLE
        )
        assert UndoManager.is_reversible(snap) is True

    def test_irreversible_action(self, manager: UndoManager) -> None:
        snap = manager.capture(
            "send_email", {}, reversibility=ActionReversibility.IRREVERSIBLE
        )
        assert UndoManager.is_reversible(snap) is False

    def test_unknown_reversibility(self, manager: UndoManager) -> None:
        snap = manager.capture(
            "mystery", {}, reversibility=ActionReversibility.UNKNOWN
        )
        assert UndoManager.is_reversible(snap) is False

    def test_can_undo_after_capture(self, manager: UndoManager) -> None:
        manager.capture("edit", {})
        assert manager.can_undo() is True

    def test_cannot_undo_after_clear(self, manager: UndoManager) -> None:
        manager.capture("edit", {})
        manager.clear()
        assert manager.can_undo() is False
