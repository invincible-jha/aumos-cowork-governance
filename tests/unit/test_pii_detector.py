"""Unit tests for detection/pii_detector.py — PiiDetector."""
from __future__ import annotations

import re

import pytest

from aumos_cowork_governance.detection.pii_detector import PiiDetector, PiiMatch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def common_us_detector() -> PiiDetector:
    return PiiDetector(jurisdictions=["common", "us"])


@pytest.fixture()
def common_only_detector() -> PiiDetector:
    return PiiDetector(jurisdictions=["common"])


@pytest.fixture()
def all_jurisdictions_detector() -> PiiDetector:
    return PiiDetector(jurisdictions=["common", "us", "eu", "india"])


# ---------------------------------------------------------------------------
# PiiMatch dataclass
# ---------------------------------------------------------------------------


class TestPiiMatch:
    def test_pii_match_is_frozen(self) -> None:
        match = PiiMatch(
            label="email_address",
            matched_text="test@example.com",
            start=0,
            end=16,
            jurisdiction="common",
        )
        with pytest.raises(Exception):
            match.label = "other"  # type: ignore[misc]

    def test_pii_match_fields(self) -> None:
        match = PiiMatch(
            label="email_address",
            matched_text="test@example.com",
            start=0,
            end=16,
            jurisdiction="common",
        )
        assert match.label == "email_address"
        assert match.matched_text == "test@example.com"
        assert match.start == 0
        assert match.end == 16
        assert match.jurisdiction == "common"


# ---------------------------------------------------------------------------
# contains_pii
# ---------------------------------------------------------------------------


class TestPiiDetectorContainsPii:
    def test_email_detected(self, common_us_detector: PiiDetector) -> None:
        assert common_us_detector.contains_pii("Email me at test@example.com") is True

    def test_no_pii_returns_false(self, common_us_detector: PiiDetector) -> None:
        assert common_us_detector.contains_pii("Hello, world!") is False

    def test_empty_string_returns_false(self, common_us_detector: PiiDetector) -> None:
        assert common_us_detector.contains_pii("") is False

    def test_phone_number_detected(self, common_us_detector: PiiDetector) -> None:
        assert common_us_detector.contains_pii("Call 555-010-1234 now") is True

    def test_ipv4_detected(self, common_us_detector: PiiDetector) -> None:
        assert common_us_detector.contains_pii("Server: 192.168.0.1") is True

    def test_synthetic_ssn_detected(self, common_us_detector: PiiDetector) -> None:
        # Synthetic SSN — not real, does not match 000/666/9xx forbidden prefixes.
        assert common_us_detector.contains_pii("SSN: 123-45-6789") is True

    def test_whitespace_only_returns_false(
        self, common_us_detector: PiiDetector
    ) -> None:
        assert common_us_detector.contains_pii("   \n\t  ") is False


# ---------------------------------------------------------------------------
# detect — returns list[PiiMatch]
# ---------------------------------------------------------------------------


class TestPiiDetectorDetect:
    def test_detect_email_returns_match(
        self, common_us_detector: PiiDetector
    ) -> None:
        matches = common_us_detector.detect("Contact: test@example.com")
        email_matches = [m for m in matches if m.label == "email_address"]
        assert len(email_matches) >= 1
        assert email_matches[0].matched_text == "test@example.com"

    def test_detect_returns_sorted_by_start(
        self, common_us_detector: PiiDetector
    ) -> None:
        text = "Email: user@example.com Phone: 555-010-1234"
        matches = common_us_detector.detect(text)
        starts = [m.start for m in matches]
        assert starts == sorted(starts)

    def test_detect_empty_text_returns_empty(
        self, common_us_detector: PiiDetector
    ) -> None:
        assert common_us_detector.detect("") == []

    def test_detect_jurisdiction_field_set(
        self, common_us_detector: PiiDetector
    ) -> None:
        matches = common_us_detector.detect("Email: test@example.com")
        email_matches = [m for m in matches if m.label == "email_address"]
        assert email_matches[0].jurisdiction == "common"

    def test_detect_multiple_emails(self, common_us_detector: PiiDetector) -> None:
        text = "To: alice@example.com and bob@example.org"
        matches = common_us_detector.detect(text)
        email_matches = [m for m in matches if m.label == "email_address"]
        assert len(email_matches) >= 2

    def test_detect_start_end_positions(
        self, common_us_detector: PiiDetector
    ) -> None:
        text = "user@example.com"
        matches = common_us_detector.detect(text)
        email_matches = [m for m in matches if m.label == "email_address"]
        assert email_matches[0].start == 0
        assert email_matches[0].end == len("user@example.com")


# ---------------------------------------------------------------------------
# detect_labels
# ---------------------------------------------------------------------------


class TestPiiDetectorDetectLabels:
    def test_detect_labels_returns_set(
        self, common_us_detector: PiiDetector
    ) -> None:
        labels = common_us_detector.detect_labels("Email: test@example.com")
        assert isinstance(labels, set)

    def test_detect_labels_contains_email(
        self, common_us_detector: PiiDetector
    ) -> None:
        labels = common_us_detector.detect_labels("test@example.com")
        assert "email_address" in labels

    def test_detect_labels_empty_text(
        self, common_us_detector: PiiDetector
    ) -> None:
        assert common_us_detector.detect_labels("") == set()


# ---------------------------------------------------------------------------
# Jurisdiction selection
# ---------------------------------------------------------------------------


class TestPiiDetectorJurisdictions:
    def test_default_uses_common_and_us(self) -> None:
        detector = PiiDetector()
        # SSN is a US pattern — should be detected with defaults.
        assert detector.contains_pii("SSN: 123-45-6789") is True

    def test_common_only_does_not_load_us_ssn_pattern(self) -> None:
        # Common patterns do NOT include SSN.
        detector = PiiDetector(jurisdictions=["common"])
        # A pure SSN without other PII should not match common-only.
        # Note: some common patterns like ZIP might match; we test SSN specifically.
        matches = detector.detect("SSN: 123-45-6789")
        ssn_matches = [m for m in matches if m.label == "us_ssn"]
        assert len(ssn_matches) == 0

    def test_eu_jurisdiction_loaded(self) -> None:
        detector = PiiDetector(jurisdictions=["eu"])
        assert detector.contains_pii("IBAN: GB29NWBK60161331926819") is True

    def test_india_jurisdiction_loaded(self) -> None:
        detector = PiiDetector(jurisdictions=["india"])
        # Synthetic Aadhaar: starts 2-9, 12 digits.
        assert detector.contains_pii("2345 6789 0123") is True

    def test_none_jurisdiction_loads_all(self) -> None:
        detector = PiiDetector(jurisdictions=None)
        # Should have patterns from all jurisdictions.
        assert len(detector._patterns) > 10

    def test_extra_patterns_added(self) -> None:
        custom_pattern = re.compile(r"\bCUSTOM-\d{4}\b")
        detector = PiiDetector(
            jurisdictions=["common"],
            extra_patterns=[("custom_id", custom_pattern)],
        )
        assert detector.contains_pii("ID: CUSTOM-1234") is True


# ---------------------------------------------------------------------------
# add_pattern at runtime
# ---------------------------------------------------------------------------


class TestPiiDetectorAddPattern:
    def test_add_pattern_detects_new_label(self) -> None:
        detector = PiiDetector(jurisdictions=["common"])
        new_pattern = re.compile(r"\bPROJ-\d+\b")
        detector.add_pattern("project_id", new_pattern, jurisdiction="custom")
        assert detector.contains_pii("See PROJ-9999 for details") is True

    def test_add_pattern_stores_jurisdiction(self) -> None:
        detector = PiiDetector(jurisdictions=["common"])
        new_pattern = re.compile(r"\bXX-\d+\b")
        detector.add_pattern("xx_id", new_pattern, jurisdiction="custom")
        matches = detector.detect("XX-1234")
        custom_matches = [m for m in matches if m.jurisdiction == "custom"]
        assert len(custom_matches) >= 1
