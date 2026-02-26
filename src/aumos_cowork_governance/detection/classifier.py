"""File sensitivity classifier.

Classifies files into four sensitivity levels based on three signals:
1. File path pattern matching (e.g., ``/confidential/``, ``*.pem``)
2. Keyword presence in content
3. PII detection in content

Sensitivity levels (ordered low to high):
    PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED

Example
-------
>>> from pathlib import Path
>>> classifier = FileClassifier()
>>> level = classifier.classify_path(Path("/data/confidential/report.csv"))
>>> level
<SensitivityLevel.CONFIDENTIAL: 'CONFIDENTIAL'>
"""
from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from aumos_cowork_governance.detection.pii_detector import PiiDetector


class SensitivityLevel(str, Enum):
    """Ordered sensitivity classification levels."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    def __ge__(self, other: "SensitivityLevel") -> bool:
        order = list(SensitivityLevel)
        return order.index(self) >= order.index(other)

    def __gt__(self, other: "SensitivityLevel") -> bool:
        order = list(SensitivityLevel)
        return order.index(self) > order.index(other)

    def __le__(self, other: "SensitivityLevel") -> bool:
        order = list(SensitivityLevel)
        return order.index(self) <= order.index(other)

    def __lt__(self, other: "SensitivityLevel") -> bool:
        order = list(SensitivityLevel)
        return order.index(self) < order.index(other)


# ---------------------------------------------------------------------------
# Path patterns
# ---------------------------------------------------------------------------
_RESTRICTED_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(secret|private|restricted|credentials|vault|keys?/|\.pem|\.key|\.p12|\.pfx|id_rsa|id_ed25519|htpasswd)"),
]
_CONFIDENTIAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(confidential|proprietary|sensitive|hipaa|phi|pii|gdpr|classified)"),
]
_INTERNAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(internal|private(?!-key)|corp|employee|hr|finance|payroll)"),
]

# ---------------------------------------------------------------------------
# Content keywords
# ---------------------------------------------------------------------------
_RESTRICTED_KEYWORDS: list[str] = [
    "top secret",
    "eyes only",
    "restricted",
    "trade secret",
    "attorney-client",
    "privileged and confidential",
]
_CONFIDENTIAL_KEYWORDS: list[str] = [
    "confidential",
    "proprietary",
    "do not distribute",
    "not for public release",
    "classified",
]
_INTERNAL_KEYWORDS: list[str] = [
    "internal use only",
    "internal only",
    "not for external",
]


class FileClassifier:
    """Classifies file sensitivity based on path, content keywords, and PII.

    Parameters
    ----------
    pii_detector:
        Optional :class:`PiiDetector` instance.  When provided, content
        containing PII is elevated to at least ``CONFIDENTIAL``.
    """

    def __init__(
        self,
        pii_detector: PiiDetector | None = None,
    ) -> None:
        self._pii_detector = pii_detector or PiiDetector()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def classify_path(self, path: Path) -> SensitivityLevel:
        """Classify sensitivity based solely on the file path.

        Parameters
        ----------
        path:
            The file path to classify.

        Returns
        -------
        SensitivityLevel
            Inferred sensitivity level.
        """
        path_str = str(path)
        if any(p.search(path_str) for p in _RESTRICTED_PATH_PATTERNS):
            return SensitivityLevel.RESTRICTED
        if any(p.search(path_str) for p in _CONFIDENTIAL_PATH_PATTERNS):
            return SensitivityLevel.CONFIDENTIAL
        if any(p.search(path_str) for p in _INTERNAL_PATH_PATTERNS):
            return SensitivityLevel.INTERNAL
        return SensitivityLevel.PUBLIC

    def classify_content(self, content: str) -> SensitivityLevel:
        """Classify sensitivity based solely on text content.

        Parameters
        ----------
        content:
            Text content to analyse.

        Returns
        -------
        SensitivityLevel
            Inferred sensitivity level.
        """
        content_lower = content.lower()

        if any(kw in content_lower for kw in _RESTRICTED_KEYWORDS):
            return SensitivityLevel.RESTRICTED

        if any(kw in content_lower for kw in _CONFIDENTIAL_KEYWORDS):
            return SensitivityLevel.CONFIDENTIAL

        if self._pii_detector.contains_pii(content):
            return SensitivityLevel.CONFIDENTIAL

        if any(kw in content_lower for kw in _INTERNAL_KEYWORDS):
            return SensitivityLevel.INTERNAL

        return SensitivityLevel.PUBLIC

    def classify(self, path: Path | None = None, content: str | None = None) -> SensitivityLevel:
        """Classify sensitivity using all available signals.

        The final level is the maximum of path-based and content-based
        classifications (most restrictive wins).

        Parameters
        ----------
        path:
            Optional file path.
        content:
            Optional text content.

        Returns
        -------
        SensitivityLevel
            Highest (most restrictive) sensitivity level found.
        """
        levels: list[SensitivityLevel] = []

        if path is not None:
            levels.append(self.classify_path(path))
        if content is not None:
            levels.append(self.classify_content(content))

        if not levels:
            return SensitivityLevel.INTERNAL  # Default for unknown inputs.

        # Return the most restrictive level.
        level_order = [
            SensitivityLevel.PUBLIC,
            SensitivityLevel.INTERNAL,
            SensitivityLevel.CONFIDENTIAL,
            SensitivityLevel.RESTRICTED,
        ]
        return max(levels, key=lambda level: level_order.index(level))
