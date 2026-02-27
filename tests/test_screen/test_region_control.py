"""Tests for aumos_cowork_governance.screen.region_control."""
from __future__ import annotations

import pytest

from aumos_cowork_governance.screen.region_control import (
    AccessDecision,
    RegionPolicy,
    ScreenRegion,
    SensitiveMasker,
)


# ---------------------------------------------------------------------------
# ScreenRegion
# ---------------------------------------------------------------------------


class TestScreenRegion:
    def test_basic_creation(self) -> None:
        r = ScreenRegion("test", x=10, y=20, width=100, height=50)
        assert r.x == 10
        assert r.y == 20
        assert r.width == 100
        assert r.height == 50

    def test_frozen(self) -> None:
        r = ScreenRegion("r", 0, 0, 100, 100)
        with pytest.raises((AttributeError, TypeError)):
            r.x = 999  # type: ignore[misc]

    def test_negative_width_raises(self) -> None:
        with pytest.raises(ValueError):
            ScreenRegion("bad", 0, 0, -1, 100)

    def test_negative_height_raises(self) -> None:
        with pytest.raises(ValueError):
            ScreenRegion("bad", 0, 0, 100, -1)

    def test_area(self) -> None:
        r = ScreenRegion("r", 0, 0, 10, 20)
        assert r.area == 200

    def test_area_zero_when_zero_dimension(self) -> None:
        r = ScreenRegion("r", 0, 0, 0, 100)
        assert r.area == 0

    def test_contains_point_inside(self) -> None:
        r = ScreenRegion("r", 10, 10, 100, 100)
        assert r.contains_point(50, 50) is True

    def test_contains_point_on_left_edge(self) -> None:
        r = ScreenRegion("r", 10, 10, 100, 100)
        assert r.contains_point(10, 50) is True

    def test_contains_point_on_right_edge_exclusive(self) -> None:
        r = ScreenRegion("r", 10, 10, 100, 100)
        assert r.contains_point(110, 50) is False

    def test_contains_point_outside(self) -> None:
        r = ScreenRegion("r", 10, 10, 100, 100)
        assert r.contains_point(5, 50) is False

    def test_overlaps_true(self) -> None:
        a = ScreenRegion("a", 0, 0, 100, 100)
        b = ScreenRegion("b", 50, 50, 100, 100)
        assert a.overlaps(b) is True
        assert b.overlaps(a) is True

    def test_overlaps_false_adjacent(self) -> None:
        a = ScreenRegion("a", 0, 0, 100, 100)
        b = ScreenRegion("b", 100, 0, 100, 100)
        assert a.overlaps(b) is False

    def test_overlaps_false_separate(self) -> None:
        a = ScreenRegion("a", 0, 0, 100, 100)
        b = ScreenRegion("b", 200, 200, 50, 50)
        assert a.overlaps(b) is False


# ---------------------------------------------------------------------------
# RegionPolicy
# ---------------------------------------------------------------------------


@pytest.fixture()
def regions() -> dict[str, ScreenRegion]:
    return {
        "form": ScreenRegion("form", 0, 0, 400, 200),
        "password": ScreenRegion("password", 0, 100, 200, 50),
        "sidebar": ScreenRegion("sidebar", 500, 0, 200, 600),
    }


class TestRegionPolicy:
    def test_allowed_region_is_allowed(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1", allowed_regions=[regions["form"]])
        assert policy.is_allowed(regions["form"]) is True

    def test_blocked_region_is_blocked(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1", blocked_regions=[regions["password"]])
        assert policy.is_blocked(regions["password"]) is True

    def test_blocked_takes_priority_over_allowed(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy(
            "sess-1",
            allowed_regions=[regions["form"]],
            blocked_regions=[regions["password"]],
        )
        # password overlaps with form, but it's in blocked list
        assert policy.is_blocked(regions["password"]) is True

    def test_default_deny(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1", default_allow=False)
        assert policy.check_access(regions["sidebar"]) == AccessDecision.NOT_DEFINED

    def test_default_allow(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1", default_allow=True)
        assert policy.check_access(regions["sidebar"]) == AccessDecision.ALLOWED

    def test_add_allowed(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1")
        policy.add_allowed(regions["form"])
        assert policy.is_allowed(regions["form"]) is True

    def test_add_blocked(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1", default_allow=True)
        policy.add_blocked(regions["password"])
        assert policy.is_blocked(regions["password"]) is True

    def test_unknown_region_not_allowed_by_default(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1", allowed_regions=[regions["form"]])
        assert policy.is_allowed(regions["sidebar"]) is False

    def test_overlapping_region_blocked(self, regions: dict[str, ScreenRegion]) -> None:
        overlapping = ScreenRegion("overlap", 50, 50, 100, 100)
        policy = RegionPolicy(
            "sess-1",
            blocked_regions=[regions["form"]],
        )
        # overlapping overlaps form
        assert policy.is_blocked(overlapping) is True


# ---------------------------------------------------------------------------
# SensitiveMasker
# ---------------------------------------------------------------------------


class TestSensitiveMasker:
    def test_blocked_region_content_masked(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1", blocked_regions=[regions["password"]])
        masker = SensitiveMasker(policy=policy)
        result = masker.mask_region_content(regions["password"], "secret123")
        assert result == "[REDACTED]"

    def test_allowed_region_content_not_masked(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1", allowed_regions=[regions["form"]])
        masker = SensitiveMasker(policy=policy)
        result = masker.mask_region_content(regions["form"], "Hello user")
        assert result == "Hello user"

    def test_undefined_region_masked_when_default_deny(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1", default_allow=False)
        masker = SensitiveMasker(policy=policy)
        result = masker.mask_region_content(regions["sidebar"], "sidebar content")
        assert result == "[REDACTED]"

    def test_undefined_region_not_masked_when_default_allow(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1", default_allow=True)
        masker = SensitiveMasker(policy=policy)
        result = masker.mask_region_content(regions["sidebar"], "sidebar content")
        assert result == "sidebar content"

    def test_custom_replacement(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy("sess-1", blocked_regions=[regions["password"]])
        masker = SensitiveMasker(policy=policy, replacement="***")
        result = masker.mask_region_content(regions["password"], "secret")
        assert result == "***"

    def test_mask_screenshot_data(self, regions: dict[str, ScreenRegion]) -> None:
        policy = RegionPolicy(
            "sess-1",
            allowed_regions=[regions["form"]],
            blocked_regions=[regions["password"]],
        )
        masker = SensitiveMasker(policy=policy)
        data = [
            (regions["form"], "public info"),
            (regions["password"], "secret123"),
        ]
        result = masker.mask_screenshot_data(data)
        assert result[0][1] == "public info"
        assert result[1][1] == "[REDACTED]"

    def test_redact_sensitive_patterns(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1")
        masker = SensitiveMasker(policy=policy)
        text = "Call me at 555-1234 or email test@example.com"
        result = masker.redact_sensitive_patterns(
            text,
            patterns=[r"\d{3}-\d{4}", r"\S+@\S+"],
        )
        assert "[REDACTED]" in result
        assert "555-1234" not in result
        assert "test@example.com" not in result

    def test_redact_patterns_empty_patterns(
        self, regions: dict[str, ScreenRegion]
    ) -> None:
        policy = RegionPolicy("sess-1")
        masker = SensitiveMasker(policy=policy)
        text = "unchanged text"
        result = masker.redact_sensitive_patterns(text, patterns=[])
        assert result == "unchanged text"
