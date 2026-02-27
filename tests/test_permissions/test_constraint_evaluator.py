"""Tests for constraint evaluators and the factory function (E8.1)."""
from __future__ import annotations

from datetime import datetime

import pytest

from aumos_cowork_governance.permissions.constraint_evaluator import (
    GlobPatternConstraint,
    RegexPatternConstraint,
    RegionConstraint,
    SizeLimitConstraint,
    TimeWindowConstraint,
    _build_constraint_from_dict,
)


# ---------------------------------------------------------------------------
# RegionConstraint
# ---------------------------------------------------------------------------

class TestRegionConstraint:
    def test_exact_prefix_match(self) -> None:
        c = RegionConstraint(allowed_paths=["/workspace"])
        assert c.evaluate("/workspace/data.csv", {}) is True

    def test_deep_path_in_region(self) -> None:
        c = RegionConstraint(allowed_paths=["/workspace"])
        assert c.evaluate("/workspace/projects/ai/data.csv", {}) is True

    def test_outside_region_denied(self) -> None:
        c = RegionConstraint(allowed_paths=["/workspace"])
        assert c.evaluate("/etc/passwd", {}) is False

    def test_multiple_allowed_paths(self) -> None:
        c = RegionConstraint(allowed_paths=["/workspace", "/tmp/uploads"])
        assert c.evaluate("/tmp/uploads/file.txt", {}) is True

    def test_partial_prefix_not_enough(self) -> None:
        c = RegionConstraint(allowed_paths=["/workspace"])
        assert c.evaluate("/workspacexyz/data.csv", {}) is False

    def test_case_sensitive_default(self) -> None:
        c = RegionConstraint(allowed_paths=["/Workspace"])
        assert c.evaluate("/workspace/data.csv", {}) is False

    def test_case_insensitive_option(self) -> None:
        c = RegionConstraint(allowed_paths=["/Workspace"], case_sensitive=False)
        assert c.evaluate("/workspace/data.csv", {}) is True

    def test_empty_allowed_paths_denies_all(self) -> None:
        c = RegionConstraint(allowed_paths=[])
        assert c.evaluate("/workspace/data.csv", {}) is False

    def test_constraint_type_identifier(self) -> None:
        c = RegionConstraint(allowed_paths=["/workspace"])
        assert c.constraint_type == "region"


# ---------------------------------------------------------------------------
# GlobPatternConstraint
# ---------------------------------------------------------------------------

class TestGlobPatternConstraint:
    def test_csv_pattern_matches(self) -> None:
        c = GlobPatternConstraint(patterns=["*.csv"])
        assert c.evaluate("/data/report.csv", {}) is True

    def test_csv_pattern_rejects_non_csv(self) -> None:
        c = GlobPatternConstraint(patterns=["*.csv"])
        assert c.evaluate("/data/report.exe", {}) is False

    def test_any_mode_passes_if_one_matches(self) -> None:
        c = GlobPatternConstraint(patterns=["*.csv", "*.json"], match_mode="any")
        assert c.evaluate("/data/report.json", {}) is True

    def test_all_mode_requires_all_to_match(self) -> None:
        c = GlobPatternConstraint(patterns=["*.csv", "*.json"], match_mode="all")
        assert c.evaluate("/data/report.csv", {}) is False

    def test_wildcard_path_pattern(self) -> None:
        c = GlobPatternConstraint(patterns=["/workspace/**"])
        assert c.evaluate("/workspace/a/b/c.txt", {}) is True

    def test_empty_patterns_deny_all(self) -> None:
        c = GlobPatternConstraint(patterns=[])
        assert c.evaluate("/data/report.csv", {}) is False

    def test_constraint_type_identifier(self) -> None:
        c = GlobPatternConstraint(patterns=["*.csv"])
        assert c.constraint_type == "glob_pattern"


# ---------------------------------------------------------------------------
# RegexPatternConstraint
# ---------------------------------------------------------------------------

class TestRegexPatternConstraint:
    def test_pattern_matches(self) -> None:
        c = RegexPatternConstraint(pattern=r"^/workspace/.*\.py$")
        assert c.evaluate("/workspace/main.py", {}) is True

    def test_pattern_rejects_non_match(self) -> None:
        c = RegexPatternConstraint(pattern=r"^/workspace/.*\.py$")
        assert c.evaluate("/workspace/main.txt", {}) is False

    def test_case_insensitive_flag(self) -> None:
        import re

        c = RegexPatternConstraint(pattern=r"\.CSV$", flags=re.IGNORECASE)
        assert c.evaluate("/data/REPORT.csv", {}) is True

    def test_partial_match_with_search_semantics(self) -> None:
        c = RegexPatternConstraint(pattern=r"secret")
        assert c.evaluate("/workspace/secret_key.txt", {}) is True

    def test_anchored_pattern_full_match(self) -> None:
        c = RegexPatternConstraint(pattern=r"^/workspace$")
        assert c.evaluate("/workspace", {}) is True
        assert c.evaluate("/workspace/extra", {}) is False

    def test_constraint_type_identifier(self) -> None:
        c = RegexPatternConstraint(pattern=r".*")
        assert c.constraint_type == "regex_pattern"


# ---------------------------------------------------------------------------
# SizeLimitConstraint
# ---------------------------------------------------------------------------

class TestSizeLimitConstraint:
    def test_size_within_limit_allowed(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.evaluate("/data/small.csv", {"size_bytes": 5_000}) is True

    def test_size_exactly_at_limit_allowed(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.evaluate("/data/exact.csv", {"size_bytes": 10_000}) is True

    def test_size_over_limit_denied(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.evaluate("/data/large.csv", {"size_bytes": 50_000}) is False

    def test_missing_size_passes_by_default(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.evaluate("/data/file.csv", {}) is True

    def test_missing_size_denied_when_strict(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000, deny_on_missing_size=True)
        assert c.evaluate("/data/file.csv", {}) is False

    def test_zero_size_allowed(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.evaluate("/data/empty.csv", {"size_bytes": 0}) is True

    def test_constraint_type_identifier(self) -> None:
        c = SizeLimitConstraint(max_bytes=10_000)
        assert c.constraint_type == "size_limit"


# ---------------------------------------------------------------------------
# TimeWindowConstraint
# ---------------------------------------------------------------------------

class TestTimeWindowConstraint:
    def test_within_business_hours(self) -> None:
        c = TimeWindowConstraint(start_hour=9, end_hour=17)
        ts = datetime(2026, 1, 5, 10, 30)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is True

    def test_outside_business_hours(self) -> None:
        c = TimeWindowConstraint(start_hour=9, end_hour=17)
        ts = datetime(2026, 1, 5, 20, 0)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is False

    def test_at_boundary_start(self) -> None:
        c = TimeWindowConstraint(start_hour=9, end_hour=17)
        ts = datetime(2026, 1, 5, 9, 0)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is True

    def test_at_boundary_end(self) -> None:
        c = TimeWindowConstraint(start_hour=9, end_hour=17)
        ts = datetime(2026, 1, 5, 17, 59)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is True

    def test_overnight_window_start(self) -> None:
        c = TimeWindowConstraint(start_hour=22, end_hour=6)
        ts = datetime(2026, 1, 5, 23, 0)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is True

    def test_overnight_window_end(self) -> None:
        c = TimeWindowConstraint(start_hour=22, end_hour=6)
        ts = datetime(2026, 1, 6, 4, 0)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is True

    def test_overnight_window_daytime_denied(self) -> None:
        c = TimeWindowConstraint(start_hour=22, end_hour=6)
        ts = datetime(2026, 1, 5, 14, 0)
        assert c.evaluate("/data/file.csv", {"timestamp": ts}) is False

    def test_weekday_restriction_allowed(self) -> None:
        c = TimeWindowConstraint(
            start_hour=0, end_hour=23, allowed_weekdays=(0, 1, 2, 3, 4)
        )
        monday = datetime(2026, 1, 5, 10, 0)  # Monday
        assert c.evaluate("/data/file.csv", {"timestamp": monday}) is True

    def test_weekday_restriction_denied_on_weekend(self) -> None:
        c = TimeWindowConstraint(
            start_hour=0, end_hour=23, allowed_weekdays=(0, 1, 2, 3, 4)
        )
        saturday = datetime(2026, 1, 10, 10, 0)  # Saturday
        assert c.evaluate("/data/file.csv", {"timestamp": saturday}) is False

    def test_missing_timestamp_passes_by_default(self) -> None:
        c = TimeWindowConstraint(start_hour=9, end_hour=17)
        assert c.evaluate("/data/file.csv", {}) is True

    def test_missing_timestamp_denied_when_strict(self) -> None:
        c = TimeWindowConstraint(
            start_hour=9, end_hour=17, deny_on_missing_time=True
        )
        assert c.evaluate("/data/file.csv", {}) is False

    def test_invalid_start_hour_raises(self) -> None:
        with pytest.raises(ValueError, match="start_hour"):
            TimeWindowConstraint(start_hour=25, end_hour=17)

    def test_invalid_end_hour_raises(self) -> None:
        with pytest.raises(ValueError, match="end_hour"):
            TimeWindowConstraint(start_hour=9, end_hour=24)

    def test_constraint_type_identifier(self) -> None:
        c = TimeWindowConstraint(start_hour=9, end_hour=17)
        assert c.constraint_type == "time_window"


# ---------------------------------------------------------------------------
# _build_constraint_from_dict factory
# ---------------------------------------------------------------------------

class TestBuildConstraintFromDict:
    def test_builds_region_constraint(self) -> None:
        c = _build_constraint_from_dict(
            {"type": "region", "allowed_paths": ["/workspace"]}
        )
        assert isinstance(c, RegionConstraint)
        assert c.evaluate("/workspace/data.csv", {}) is True

    def test_builds_glob_pattern_constraint(self) -> None:
        c = _build_constraint_from_dict(
            {"type": "glob_pattern", "patterns": ["*.csv"]}
        )
        assert isinstance(c, GlobPatternConstraint)
        assert c.evaluate("data.csv", {}) is True

    def test_builds_regex_pattern_constraint(self) -> None:
        c = _build_constraint_from_dict(
            {"type": "regex_pattern", "pattern": r"\.csv$"}
        )
        assert isinstance(c, RegexPatternConstraint)
        assert c.evaluate("data.csv", {}) is True

    def test_builds_size_limit_constraint(self) -> None:
        c = _build_constraint_from_dict(
            {"type": "size_limit", "max_bytes": 1000}
        )
        assert isinstance(c, SizeLimitConstraint)
        assert c.evaluate("data.csv", {"size_bytes": 500}) is True

    def test_builds_time_window_constraint(self) -> None:
        c = _build_constraint_from_dict(
            {"type": "time_window", "start_hour": 9, "end_hour": 17}
        )
        assert isinstance(c, TimeWindowConstraint)

    def test_missing_type_raises(self) -> None:
        with pytest.raises(ValueError, match="type"):
            _build_constraint_from_dict({"allowed_paths": ["/workspace"]})

    def test_unknown_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown constraint type"):
            _build_constraint_from_dict({"type": "magic_constraint"})

    def test_region_case_insensitive_option(self) -> None:
        c = _build_constraint_from_dict(
            {
                "type": "region",
                "allowed_paths": ["/Workspace"],
                "case_sensitive": False,
            }
        )
        assert isinstance(c, RegionConstraint)
        assert c.case_sensitive is False

    def test_time_window_weekday_restriction(self) -> None:
        c = _build_constraint_from_dict(
            {
                "type": "time_window",
                "start_hour": 9,
                "end_hour": 17,
                "allowed_weekdays": [0, 1, 2, 3, 4],
            }
        )
        assert isinstance(c, TimeWindowConstraint)
        assert c.allowed_weekdays == (0, 1, 2, 3, 4)
