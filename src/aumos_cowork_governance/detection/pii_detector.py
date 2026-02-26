"""Regex-based PII detector with jurisdiction-aware pattern sets.

The detector scans text for matches against a configurable set of
regex patterns grouped by jurisdiction (common, us, eu, india).

Example
-------
>>> detector = PiiDetector(jurisdictions=["common", "us"])
>>> detector.contains_pii("Call me at 415-555-0100")
True
>>> matches = detector.detect("Email: alice@example.com")
>>> matches[0].label
'email_address'
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from aumos_cowork_governance.detection.patterns.common import COMMON_PATTERNS
from aumos_cowork_governance.detection.patterns.eu import EU_PATTERNS
from aumos_cowork_governance.detection.patterns.india import INDIA_PATTERNS
from aumos_cowork_governance.detection.patterns.us import US_PATTERNS


@dataclass(frozen=True)
class PiiMatch:
    """Represents a single PII pattern match within a text.

    Attributes
    ----------
    label:
        Human-readable PII type label (e.g., ``"email_address"``).
    matched_text:
        The exact substring that was matched.
    start:
        Start index within the scanned text.
    end:
        End index within the scanned text.
    jurisdiction:
        Jurisdiction the pattern belongs to
        (``"common"``, ``"us"``, ``"eu"``, ``"india"``).
    """

    label: str
    matched_text: str
    start: int
    end: int
    jurisdiction: str


# Mapping of jurisdiction name to pattern list.
_JURISDICTION_MAP: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "common": COMMON_PATTERNS,
    "us": US_PATTERNS,
    "eu": EU_PATTERNS,
    "india": INDIA_PATTERNS,
}

_ALL_JURISDICTIONS: list[str] = list(_JURISDICTION_MAP.keys())


class PiiDetector:
    """Scans text for PII using compiled regex patterns.

    Parameters
    ----------
    jurisdictions:
        Which jurisdiction pattern sets to load.  Defaults to
        ``["common", "us"]``.  Pass ``None`` to load all jurisdictions.
    extra_patterns:
        Additional ``(label, compiled_pattern)`` tuples to include.
    """

    def __init__(
        self,
        jurisdictions: list[str] | None = None,
        extra_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        selected = jurisdictions if jurisdictions is not None else ["common", "us"]
        self._patterns: list[tuple[str, re.Pattern[str], str]] = []

        for jurisdiction in selected:
            for label, pattern in _JURISDICTION_MAP.get(jurisdiction, []):
                self._patterns.append((label, pattern, jurisdiction))

        for label, pattern in (extra_patterns or []):
            self._patterns.append((label, pattern, "custom"))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def contains_pii(self, text: str) -> bool:
        """Return ``True`` as soon as any PII pattern matches.

        Parameters
        ----------
        text:
            The string to scan.

        Returns
        -------
        bool
            ``True`` when at least one pattern matches.
        """
        for _, pattern, _ in self._patterns:
            if pattern.search(text):
                return True
        return False

    def detect(self, text: str) -> list[PiiMatch]:
        """Return all PII matches found in the text.

        Parameters
        ----------
        text:
            The string to scan.

        Returns
        -------
        list[PiiMatch]
            All matches, in order of appearance.  Overlapping matches
            from different patterns are included.
        """
        matches: list[PiiMatch] = []
        for label, pattern, jurisdiction in self._patterns:
            for m in pattern.finditer(text):
                matches.append(
                    PiiMatch(
                        label=label,
                        matched_text=m.group(),
                        start=m.start(),
                        end=m.end(),
                        jurisdiction=jurisdiction,
                    )
                )
        matches.sort(key=lambda m: m.start)
        return matches

    def detect_labels(self, text: str) -> set[str]:
        """Return the set of PII type labels found in the text.

        Parameters
        ----------
        text:
            The string to scan.

        Returns
        -------
        set[str]
            Unique PII label names matched.
        """
        return {m.label for m in self.detect(text)}

    def add_pattern(self, label: str, pattern: re.Pattern[str], jurisdiction: str = "custom") -> None:
        """Add a custom pattern to the detector at runtime.

        Parameters
        ----------
        label:
            Human-readable label for the new pattern.
        pattern:
            Compiled regex pattern.
        jurisdiction:
            Jurisdiction label (default: ``"custom"``).
        """
        self._patterns.append((label, pattern, jurisdiction))
