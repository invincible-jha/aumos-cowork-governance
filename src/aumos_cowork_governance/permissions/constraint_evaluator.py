"""Composable constraint evaluators for the action permission system (E8.1).

Each ConstraintEvaluator subclass evaluates one specific kind of constraint
against a resource_path and optional context dictionary. Constraints are
composable — a PermissionRule can hold any number of constraints, all of
which must pass (AND semantics).

Supported constraint types:
- RegionConstraint      — resource_path must be within allowed path prefixes
- GlobPatternConstraint — resource_path must match one or more glob patterns
- RegexPatternConstraint — resource_path must match a regular expression
- SizeLimitConstraint   — context["size_bytes"] must not exceed the limit
- TimeWindowConstraint  — context["timestamp"] must fall within allowed hours

Factory
-------
Use ``_build_constraint_from_dict`` to construct the right subclass from
a config dictionary (used internally by PermissionRule.from_dict).
"""
from __future__ import annotations

import fnmatch
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, time

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class ConstraintEvaluator(ABC):
    """Abstract base for permission constraints.

    Subclasses implement :meth:`evaluate` to decide whether a given
    resource_path (and optional context) satisfies the constraint.
    """

    @abstractmethod
    def evaluate(self, resource_path: str, context: dict[str, object]) -> bool:
        """Return True if the constraint is satisfied.

        Parameters
        ----------
        resource_path:
            The resource path being evaluated.
        context:
            Additional context (e.g. file size, current timestamp).

        Returns
        -------
        bool
        """

    @property
    @abstractmethod
    def constraint_type(self) -> str:
        """Return the short type identifier for this constraint."""


# ---------------------------------------------------------------------------
# RegionConstraint
# ---------------------------------------------------------------------------


@dataclass
class RegionConstraint(ConstraintEvaluator):
    """Restrict actions to resources within allowed directory regions.

    A resource_path satisfies this constraint when it starts with at least
    one of the ``allowed_paths`` prefixes.

    Attributes
    ----------
    allowed_paths:
        List of path prefixes that are permitted.
    case_sensitive:
        Whether path comparison is case-sensitive. Default True.

    Examples
    --------
    ::

        c = RegionConstraint(allowed_paths=["/workspace", "/tmp/uploads"])
        assert c.evaluate("/workspace/data.csv", {}) is True
        assert c.evaluate("/etc/passwd", {}) is False
    """

    allowed_paths: list[str]
    case_sensitive: bool = True

    @property
    def constraint_type(self) -> str:
        return "region"

    def evaluate(self, resource_path: str, context: dict[str, object]) -> bool:
        path = resource_path if self.case_sensitive else resource_path.lower()
        for prefix in self.allowed_paths:
            effective_prefix = prefix if self.case_sensitive else prefix.lower()
            # Require the prefix to be followed by a path separator or be an
            # exact match, so that "/workspace" does not match "/workspacexyz".
            if path == effective_prefix or path.startswith(
                effective_prefix.rstrip("/") + "/"
            ):
                return True
        return False


# ---------------------------------------------------------------------------
# GlobPatternConstraint
# ---------------------------------------------------------------------------


@dataclass
class GlobPatternConstraint(ConstraintEvaluator):
    """Permit resources matching one or more glob patterns.

    Uses Python's ``fnmatch`` for pattern matching. The resource_path
    satisfies the constraint when it matches at least one pattern.

    Attributes
    ----------
    patterns:
        List of glob patterns (e.g. ``"*.csv"``, ``"/workspace/**/*.json"``).
    match_mode:
        ``"any"`` — passes if any pattern matches (default).
        ``"all"`` — passes only if all patterns match.

    Examples
    --------
    ::

        c = GlobPatternConstraint(patterns=["*.csv", "*.json"])
        assert c.evaluate("/data/report.csv", {}) is True
        assert c.evaluate("/data/report.exe", {}) is False
    """

    patterns: list[str]
    match_mode: str = "any"

    @property
    def constraint_type(self) -> str:
        return "glob_pattern"

    def evaluate(self, resource_path: str, context: dict[str, object]) -> bool:
        results = [fnmatch.fnmatch(resource_path, pat) for pat in self.patterns]
        if self.match_mode == "all":
            return all(results)
        return any(results)


# ---------------------------------------------------------------------------
# RegexPatternConstraint
# ---------------------------------------------------------------------------


@dataclass
class RegexPatternConstraint(ConstraintEvaluator):
    """Permit resources matching a compiled regular expression.

    The resource_path satisfies the constraint when the pattern produces a
    match anywhere in the path string (``re.search`` semantics). Use ``^``
    and ``$`` anchors for full-string matching.

    Attributes
    ----------
    pattern:
        Regular expression pattern string.
    flags:
        Regex flags as an integer (e.g. ``re.IGNORECASE``). Default 0.

    Examples
    --------
    ::

        c = RegexPatternConstraint(pattern=r"^/workspace/.*\\.py$")
        assert c.evaluate("/workspace/main.py", {}) is True
        assert c.evaluate("/workspace/main.txt", {}) is False
    """

    pattern: str
    flags: int = 0

    def __post_init__(self) -> None:
        self._compiled: re.Pattern[str] = re.compile(self.pattern, self.flags)

    @property
    def constraint_type(self) -> str:
        return "regex_pattern"

    def evaluate(self, resource_path: str, context: dict[str, object]) -> bool:
        return bool(self._compiled.search(resource_path))


# ---------------------------------------------------------------------------
# SizeLimitConstraint
# ---------------------------------------------------------------------------


@dataclass
class SizeLimitConstraint(ConstraintEvaluator):
    """Restrict actions on resources that exceed a size limit.

    Reads ``size_bytes`` from the context dictionary. If absent, the
    constraint passes (size is unknown — rely on other guards).

    Attributes
    ----------
    max_bytes:
        Maximum allowed resource size in bytes.
    deny_on_missing_size:
        When ``True``, the constraint fails if ``size_bytes`` is not
        present in context. Default ``False`` (pass on unknown).

    Examples
    --------
    ::

        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.evaluate("/data/small.csv", {"size_bytes": 5_000}) is True
        assert c.evaluate("/data/large.csv", {"size_bytes": 50_000}) is False
    """

    max_bytes: int
    deny_on_missing_size: bool = False

    @property
    def constraint_type(self) -> str:
        return "size_limit"

    def evaluate(self, resource_path: str, context: dict[str, object]) -> bool:
        size = context.get("size_bytes")
        if size is None:
            return not self.deny_on_missing_size
        try:
            return int(size) <= self.max_bytes
        except (TypeError, ValueError):
            logger.warning(
                "SizeLimitConstraint: could not cast size_bytes=%r to int for %s",
                size,
                resource_path,
            )
            return not self.deny_on_missing_size


# ---------------------------------------------------------------------------
# TimeWindowConstraint
# ---------------------------------------------------------------------------


@dataclass
class TimeWindowConstraint(ConstraintEvaluator):
    """Restrict actions to permitted hours-of-day windows.

    Reads ``timestamp`` (a ``datetime`` object) from the context. If absent,
    the constraint passes unless ``deny_on_missing_time`` is set.

    Attributes
    ----------
    start_hour:
        Start of the permitted window (0–23, inclusive).
    end_hour:
        End of the permitted window (0–23, inclusive). May be less than
        ``start_hour`` to express overnight windows (e.g. 22–06).
    deny_on_missing_time:
        When ``True``, the constraint fails if ``timestamp`` is not in context.
        Default ``False``.
    allowed_weekdays:
        Tuple of weekday integers (0=Monday … 6=Sunday). If empty, all days
        are permitted.

    Examples
    --------
    ::

        # Allow actions between 09:00 and 17:00 on weekdays
        c = TimeWindowConstraint(
            start_hour=9,
            end_hour=17,
            allowed_weekdays=(0, 1, 2, 3, 4),
        )
        from datetime import datetime
        assert c.evaluate("/data/file.csv", {"timestamp": datetime(2026, 1, 5, 10)}) is True
        assert c.evaluate("/data/file.csv", {"timestamp": datetime(2026, 1, 5, 20)}) is False
    """

    start_hour: int
    end_hour: int
    deny_on_missing_time: bool = False
    allowed_weekdays: tuple[int, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0 <= self.start_hour <= 23:
            raise ValueError(
                f"TimeWindowConstraint.start_hour must be 0–23; got {self.start_hour!r}."
            )
        if not 0 <= self.end_hour <= 23:
            raise ValueError(
                f"TimeWindowConstraint.end_hour must be 0–23; got {self.end_hour!r}."
            )
        for day in self.allowed_weekdays:
            if not 0 <= day <= 6:
                raise ValueError(
                    f"TimeWindowConstraint.allowed_weekdays contains invalid day {day!r}."
                )

    @property
    def constraint_type(self) -> str:
        return "time_window"

    def evaluate(self, resource_path: str, context: dict[str, object]) -> bool:
        timestamp = context.get("timestamp")
        if timestamp is None:
            return not self.deny_on_missing_time

        if not isinstance(timestamp, datetime):
            logger.warning(
                "TimeWindowConstraint: expected datetime, got %r for %s",
                type(timestamp),
                resource_path,
            )
            return not self.deny_on_missing_time

        # Weekday check
        if self.allowed_weekdays and timestamp.weekday() not in self.allowed_weekdays:
            return False

        # Hour range check — supports overnight windows (e.g. start=22, end=6)
        hour = timestamp.hour
        if self.start_hour <= self.end_hour:
            return self.start_hour <= hour <= self.end_hour
        else:
            # Overnight window: e.g. 22–06 means hour >= 22 OR hour <= 6
            return hour >= self.start_hour or hour <= self.end_hour


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_CONSTRAINT_TYPE_MAP: dict[str, type[ConstraintEvaluator]] = {
    "region": RegionConstraint,
    "glob_pattern": GlobPatternConstraint,
    "regex_pattern": RegexPatternConstraint,
    "size_limit": SizeLimitConstraint,
    "time_window": TimeWindowConstraint,
}


def _build_constraint_from_dict(data: dict[str, object]) -> ConstraintEvaluator:
    """Build a ConstraintEvaluator subclass from a config dictionary.

    Parameters
    ----------
    data:
        Dictionary with at minimum a ``type`` key indicating which constraint
        to construct. Additional keys are passed as constructor arguments.

    Returns
    -------
    ConstraintEvaluator

    Raises
    ------
    ValueError
        If the ``type`` key is missing or unknown.
    """
    constraint_type = str(data.get("type", ""))
    if not constraint_type:
        raise ValueError("Constraint dict must have a 'type' key.")
    if constraint_type not in _CONSTRAINT_TYPE_MAP:
        raise ValueError(
            f"Unknown constraint type {constraint_type!r}. "
            f"Known types: {sorted(_CONSTRAINT_TYPE_MAP.keys())}."
        )

    # Verify type is in map — already validated above; match below handles dispatch.
    match constraint_type:
        case "region":
            allowed_paths = list(data.get("allowed_paths", []))  # type: ignore[arg-type]
            case_sensitive = bool(data.get("case_sensitive", True))
            return RegionConstraint(
                allowed_paths=allowed_paths, case_sensitive=case_sensitive
            )

        case "glob_pattern":
            patterns = list(data.get("patterns", []))  # type: ignore[arg-type]
            match_mode = str(data.get("match_mode", "any"))
            return GlobPatternConstraint(patterns=patterns, match_mode=match_mode)

        case "regex_pattern":
            pattern = str(data.get("pattern", ""))
            flags = int(data.get("flags", 0))
            return RegexPatternConstraint(pattern=pattern, flags=flags)

        case "size_limit":
            max_bytes = int(data.get("max_bytes", 0))
            deny_on_missing_size = bool(data.get("deny_on_missing_size", False))
            return SizeLimitConstraint(
                max_bytes=max_bytes, deny_on_missing_size=deny_on_missing_size
            )

        case "time_window":
            start_hour = int(data.get("start_hour", 0))
            end_hour = int(data.get("end_hour", 23))
            deny_on_missing_time = bool(data.get("deny_on_missing_time", False))
            raw_days = data.get("allowed_weekdays", [])
            allowed_weekdays: tuple[int, ...] = tuple(int(d) for d in raw_days)  # type: ignore[union-attr]
            return TimeWindowConstraint(
                start_hour=start_hour,
                end_hour=end_hour,
                deny_on_missing_time=deny_on_missing_time,
                allowed_weekdays=allowed_weekdays,
            )

        case _:
            # Should be unreachable due to the map lookup above.
            raise ValueError(f"Unhandled constraint type: {constraint_type!r}")
