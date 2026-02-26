"""PII redactor.

Replaces detected PII in text with placeholder tokens of the form
``[REDACTED:<LABEL>]``.  The redactor applies patterns from a
PiiDetector and replaces all matches non-destructively (preserving
the structure of non-PII text).

Example
-------
>>> redactor = PiiRedactor()
>>> redactor.redact("Send invoice to alice@example.com by Friday.")
'Send invoice to [REDACTED:EMAIL_ADDRESS] by Friday.'
"""
from __future__ import annotations

import re

from aumos_cowork_governance.detection.pii_detector import PiiDetector, PiiMatch


class PiiRedactor:
    """Redacts PII matches from text using pattern replacement.

    Parameters
    ----------
    detector:
        Optional :class:`PiiDetector` instance.  A default detector
        (common + US jurisdictions) is created when omitted.
    placeholder_template:
        Format string for the replacement token.  Use ``{label}`` to
        insert the PII type label.  Default: ``"[REDACTED:{label}]"``.
    """

    def __init__(
        self,
        detector: PiiDetector | None = None,
        placeholder_template: str = "[REDACTED:{label}]",
    ) -> None:
        self._detector = detector or PiiDetector()
        self._template = placeholder_template

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def redact(self, text: str) -> str:
        """Return a copy of ``text`` with all PII replaced by placeholders.

        Overlapping matches are resolved by preferring the earlier start
        position.  When two matches start at the same position, the longer
        match wins.

        Parameters
        ----------
        text:
            Input text to redact.

        Returns
        -------
        str
            Redacted text.
        """
        matches = self._detector.detect(text)
        if not matches:
            return text

        # Resolve overlaps: build a non-overlapping list sorted by start.
        resolved = self._resolve_overlaps(matches)

        # Build the output by splicing in placeholders.
        parts: list[str] = []
        cursor = 0
        for match in resolved:
            if match.start > cursor:
                parts.append(text[cursor : match.start])
            placeholder = self._template.format(label=match.label.upper())
            parts.append(placeholder)
            cursor = match.end

        if cursor < len(text):
            parts.append(text[cursor:])

        return "".join(parts)

    def redact_with_report(self, text: str) -> tuple[str, list[PiiMatch]]:
        """Redact PII and return both the redacted text and match details.

        Parameters
        ----------
        text:
            Input text to redact.

        Returns
        -------
        tuple[str, list[PiiMatch]]
            ``(redacted_text, matches_applied)`` where ``matches_applied``
            is the deduplicated, non-overlapping list of matches that were
            replaced.
        """
        matches = self._detector.detect(text)
        if not matches:
            return text, []

        resolved = self._resolve_overlaps(matches)

        parts: list[str] = []
        cursor = 0
        for match in resolved:
            if match.start > cursor:
                parts.append(text[cursor : match.start])
            placeholder = self._template.format(label=match.label.upper())
            parts.append(placeholder)
            cursor = match.end

        if cursor < len(text):
            parts.append(text[cursor:])

        return "".join(parts), resolved

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_overlaps(matches: list[PiiMatch]) -> list[PiiMatch]:
        """Remove overlapping matches, keeping the earlier/longer match."""
        sorted_matches = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
        resolved: list[PiiMatch] = []
        last_end = -1
        for match in sorted_matches:
            if match.start >= last_end:
                resolved.append(match)
                last_end = match.end
        return resolved
