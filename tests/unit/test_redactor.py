"""Unit tests for detection/redactor.py — PiiRedactor."""
from __future__ import annotations

import re

import pytest

from aumos_cowork_governance.detection.pii_detector import PiiDetector
from aumos_cowork_governance.detection.redactor import PiiRedactor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def redactor() -> PiiRedactor:
    return PiiRedactor()


@pytest.fixture()
def custom_redactor() -> PiiRedactor:
    detector = PiiDetector(jurisdictions=["common"])
    return PiiRedactor(detector=detector, placeholder_template="***{label}***")


# ---------------------------------------------------------------------------
# redact — basic behaviour
# ---------------------------------------------------------------------------


class TestPiiRedactorRedact:
    def test_redact_email_is_replaced(self, redactor: PiiRedactor) -> None:
        result = redactor.redact("Send invoice to test@example.com by Friday.")
        assert "test@example.com" not in result
        assert "[REDACTED:" in result

    def test_redact_email_placeholder_label(self, redactor: PiiRedactor) -> None:
        result = redactor.redact("Email: user@example.com")
        assert "[REDACTED:EMAIL_ADDRESS]" in result

    def test_redact_no_pii_returns_original(self, redactor: PiiRedactor) -> None:
        original = "This text has no PII whatsoever."
        result = redactor.redact(original)
        assert result == original

    def test_redact_empty_string(self, redactor: PiiRedactor) -> None:
        assert redactor.redact("") == ""

    def test_redact_preserves_surrounding_text(self, redactor: PiiRedactor) -> None:
        result = redactor.redact("Hello test@example.com goodbye")
        assert result.startswith("Hello ")
        assert result.endswith(" goodbye")

    def test_redact_multiple_pii_items(self, redactor: PiiRedactor) -> None:
        text = "Email: a@example.com IP: 192.168.0.1"
        result = redactor.redact(text)
        assert "a@example.com" not in result
        assert "192.168.0.1" not in result

    def test_redact_custom_template(self, custom_redactor: PiiRedactor) -> None:
        result = custom_redactor.redact("Email: user@example.com")
        assert "***EMAIL_ADDRESS***" in result

    def test_redact_synthetic_ssn(self, redactor: PiiRedactor) -> None:
        # Synthetic SSN (not real, safe for testing).
        result = redactor.redact("SSN: 123-45-6789")
        assert "123-45-6789" not in result

    def test_redact_label_uppercased(self, redactor: PiiRedactor) -> None:
        result = redactor.redact("test@example.com")
        # Label should be uppercased in placeholder.
        assert "[REDACTED:EMAIL_ADDRESS]" in result

    def test_redact_only_pii_portions_replaced(self, redactor: PiiRedactor) -> None:
        text = "Contact test@example.com for details"
        result = redactor.redact(text)
        assert "Contact" in result
        assert "for details" in result


# ---------------------------------------------------------------------------
# redact_with_report
# ---------------------------------------------------------------------------


class TestPiiRedactorRedactWithReport:
    def test_returns_tuple(self, redactor: PiiRedactor) -> None:
        result = redactor.redact_with_report("Email: test@example.com")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_redacted_text_has_placeholder(self, redactor: PiiRedactor) -> None:
        redacted_text, matches = redactor.redact_with_report("test@example.com")
        assert "[REDACTED:" in redacted_text

    def test_matches_list_non_empty_for_pii(self, redactor: PiiRedactor) -> None:
        _, matches = redactor.redact_with_report("test@example.com")
        assert len(matches) >= 1

    def test_matches_list_empty_for_no_pii(self, redactor: PiiRedactor) -> None:
        redacted_text, matches = redactor.redact_with_report("No PII here.")
        assert matches == []
        assert redacted_text == "No PII here."

    def test_match_label_is_correct(self, redactor: PiiRedactor) -> None:
        _, matches = redactor.redact_with_report("test@example.com")
        email_matches = [m for m in matches if m.label == "email_address"]
        assert len(email_matches) >= 1


# ---------------------------------------------------------------------------
# _resolve_overlaps (internal, tested via behaviour)
# ---------------------------------------------------------------------------


class TestPiiRedactorOverlapResolution:
    def test_overlapping_matches_resolved(self) -> None:
        # Use a custom detector with overlapping patterns.
        pattern_a = re.compile(r"\babc\d+\b")
        pattern_b = re.compile(r"\babc\b")
        detector = PiiDetector(
            jurisdictions=[],
            extra_patterns=[("label_a", pattern_a), ("label_b", pattern_b)],
        )
        redactor = PiiRedactor(detector=detector)
        result = redactor.redact("word abc123 word")
        # Should not have double-replacement artifacts.
        assert result.count("[REDACTED:") == 1

    def test_adjacent_non_overlapping_both_replaced(self) -> None:
        detector = PiiDetector(jurisdictions=["common"])
        redactor = PiiRedactor(detector=detector)
        text = "a@b.com c@d.org"
        result = redactor.redact(text)
        # Both emails should be replaced.
        assert result.count("[REDACTED:EMAIL_ADDRESS]") >= 2

    def test_resolve_overlaps_prefers_earlier_start(self) -> None:
        from aumos_cowork_governance.detection.pii_detector import PiiMatch

        match_a = PiiMatch(
            label="a", matched_text="abc", start=0, end=3, jurisdiction="test"
        )
        match_b = PiiMatch(
            label="b", matched_text="ab", start=0, end=2, jurisdiction="test"
        )
        resolved = PiiRedactor._resolve_overlaps([match_b, match_a])
        # Same start — longer match (end=3) should win.
        assert len(resolved) == 1
        assert resolved[0].label == "a"
