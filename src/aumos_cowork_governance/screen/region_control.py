"""Screen region access control.

Defines spatial regions of a screen and policies governing which regions
an agent may read from or write to.  Sensitive regions are masked by the
:class:`SensitiveMasker` before content is passed to the agent.

This implements a spatial access control model: the agent declares what
screen regions it will interact with, and the governance layer enforces
allow/block lists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Screen region dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScreenRegion:
    """A rectangular region of the screen.

    Coordinates are in screen pixels (top-left origin).

    Attributes
    ----------
    name:
        Human-readable identifier for this region (e.g. "password_field").
    x:
        Left edge of the region in pixels.
    y:
        Top edge of the region in pixels.
    width:
        Width of the region in pixels.
    height:
        Height of the region in pixels.
    description:
        Optional description of what this region contains.
    """

    name: str
    x: int
    y: int
    width: int
    height: int
    description: str = ""

    def __post_init__(self) -> None:
        if self.width < 0:
            raise ValueError(f"ScreenRegion width must be non-negative, got {self.width}")
        if self.height < 0:
            raise ValueError(f"ScreenRegion height must be non-negative, got {self.height}")

    def contains_point(self, px: int, py: int) -> bool:
        """Return True if the point (px, py) falls within this region.

        Parameters
        ----------
        px:
            X coordinate to test.
        py:
            Y coordinate to test.

        Returns
        -------
        bool
            True when the point is inside the region boundaries.
        """
        return self.x <= px < self.x + self.width and self.y <= py < self.y + self.height

    def overlaps(self, other: ScreenRegion) -> bool:
        """Return True if this region overlaps with *other*.

        Parameters
        ----------
        other:
            Another :class:`ScreenRegion` to compare with.

        Returns
        -------
        bool
            True when the two regions share at least one pixel.
        """
        return (
            self.x < other.x + other.width
            and self.x + self.width > other.x
            and self.y < other.y + other.height
            and self.y + self.height > other.y
        )

    @property
    def area(self) -> int:
        """Return the area of this region in pixels squared."""
        return self.width * self.height


# ---------------------------------------------------------------------------
# Region policy
# ---------------------------------------------------------------------------


class AccessDecision(str, Enum):
    """Result of a policy access check."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    NOT_DEFINED = "not_defined"


@dataclass
class RegionPolicy:
    """Policy governing screen region access for an agent session.

    Regions are evaluated in order: blocked list takes precedence over
    allowed list.  Regions not appearing in either list are subject to
    the *default_allow* flag.

    Attributes
    ----------
    session_id:
        Identifier for the session this policy applies to.
    allowed_regions:
        Regions the agent is explicitly permitted to access.
    blocked_regions:
        Regions the agent is explicitly forbidden from accessing.
    default_allow:
        Whether to allow access to regions not explicitly listed.
        Defaults to False (deny by default).
    """

    session_id: str
    allowed_regions: list[ScreenRegion] = field(default_factory=list)
    blocked_regions: list[ScreenRegion] = field(default_factory=list)
    default_allow: bool = False

    def check_access(self, region: ScreenRegion) -> AccessDecision:
        """Determine whether *region* is accessible under this policy.

        Blocked regions take priority over allowed regions.  Name-based
        matching takes priority over spatial overlap so that an explicitly
        allowed region is not shadowed by a separate overlapping blocked
        region.

        Parameters
        ----------
        region:
            The :class:`ScreenRegion` to evaluate.

        Returns
        -------
        AccessDecision
            The access decision for this region.
        """
        # Name-identity check takes highest priority.
        for allowed in self.allowed_regions:
            if allowed.name == region.name:
                return AccessDecision.ALLOWED

        for blocked in self.blocked_regions:
            if blocked.name == region.name:
                return AccessDecision.BLOCKED

        # Spatial overlap check — a region not named in either list may still
        # overlap with a blocked or allowed region.
        for blocked in self.blocked_regions:
            if blocked.overlaps(region):
                return AccessDecision.BLOCKED

        for allowed in self.allowed_regions:
            if allowed.overlaps(region):
                return AccessDecision.ALLOWED

        # Default
        if self.default_allow:
            return AccessDecision.ALLOWED
        return AccessDecision.NOT_DEFINED

    def is_allowed(self, region: ScreenRegion) -> bool:
        """Return True if *region* is accessible.

        Parameters
        ----------
        region:
            The region to check.

        Returns
        -------
        bool
            True when access decision is ALLOWED.
        """
        return self.check_access(region) == AccessDecision.ALLOWED

    def is_blocked(self, region: ScreenRegion) -> bool:
        """Return True if *region* is blocked.

        Parameters
        ----------
        region:
            The region to check.

        Returns
        -------
        bool
            True when access decision is BLOCKED.
        """
        return self.check_access(region) == AccessDecision.BLOCKED

    def add_allowed(self, region: ScreenRegion) -> None:
        """Add *region* to the allow list."""
        self.allowed_regions.append(region)

    def add_blocked(self, region: ScreenRegion) -> None:
        """Add *region* to the block list."""
        self.blocked_regions.append(region)


# ---------------------------------------------------------------------------
# Sensitive masker
# ---------------------------------------------------------------------------

_REPLACEMENT = "[REDACTED]"


@dataclass
class SensitiveMasker:
    """Redact content from blocked screen regions.

    The masker replaces text content associated with blocked regions with
    a placeholder string before the content is forwarded to the agent.

    Attributes
    ----------
    policy:
        The :class:`RegionPolicy` to apply when deciding what to mask.
    replacement:
        The string used to replace masked content (default: "[REDACTED]").
    """

    policy: RegionPolicy
    replacement: str = _REPLACEMENT

    def mask_region_content(
        self, region: ScreenRegion, content: str
    ) -> str:
        """Mask *content* if *region* is blocked by the policy.

        Parameters
        ----------
        region:
            The region from which *content* was captured.
        content:
            The text content captured from the region.

        Returns
        -------
        str
            The original *content* if the region is allowed; the
            :attr:`replacement` string if blocked or not defined.
        """
        if self.policy.is_blocked(region):
            return self.replacement
        if not self.policy.is_allowed(region):
            # Not defined and default_allow=False → mask
            if not self.policy.default_allow:
                return self.replacement
        return content

    def mask_screenshot_data(
        self, regions_with_content: list[tuple[ScreenRegion, str]]
    ) -> list[tuple[ScreenRegion, str]]:
        """Apply masking across multiple (region, content) pairs.

        Parameters
        ----------
        regions_with_content:
            List of (region, text) tuples extracted from a screenshot.

        Returns
        -------
        list[tuple[ScreenRegion, str]]
            Same list with blocked/undefined region content replaced.
        """
        return [
            (region, self.mask_region_content(region, content))
            for region, content in regions_with_content
        ]

    def redact_sensitive_patterns(
        self, text: str, patterns: list[str]
    ) -> str:
        """Apply regex-based redaction to *text* regardless of region.

        Parameters
        ----------
        text:
            Free-form text to sanitise.
        patterns:
            List of regular expression patterns; matches are replaced.

        Returns
        -------
        str
            The sanitised text with all pattern matches replaced.
        """
        result = text
        for pattern in patterns:
            result = re.sub(pattern, self.replacement, result)
        return result


__all__ = [
    "AccessDecision",
    "RegionPolicy",
    "ScreenRegion",
    "SensitiveMasker",
]
