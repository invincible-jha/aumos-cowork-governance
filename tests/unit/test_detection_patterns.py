"""Unit tests for detection/patterns — common, us, eu, india."""
from __future__ import annotations

import re

import pytest

from aumos_cowork_governance.detection.patterns.common import (
    COMMON_PATTERNS,
    CREDIT_CARD,
    DATE_OF_BIRTH,
    EMAIL,
    FULL_NAME,
    IPV4_ADDRESS,
    PHONE,
    PHONE_INTERNATIONAL,
)
from aumos_cowork_governance.detection.patterns.eu import (
    BIC,
    EU_PATTERNS,
    EU_VAT,
    FR_INSEE,
    IBAN,
)
from aumos_cowork_governance.detection.patterns.india import (
    AADHAAR,
    GSTIN,
    IN_MOBILE,
    INDIA_PATTERNS,
    PAN,
    VOTER_ID,
)
from aumos_cowork_governance.detection.patterns.us import (
    EIN,
    SSN,
    US_PATTERNS,
    US_ZIP,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matches(pattern_tuple: tuple[str, re.Pattern[str]], text: str) -> bool:
    _, pattern = pattern_tuple
    return bool(pattern.search(text))


# ---------------------------------------------------------------------------
# Common patterns
# ---------------------------------------------------------------------------


class TestCommonPatterns:
    def test_email_matches_standard_address(self) -> None:
        assert _matches(EMAIL, "Contact: test@example.com for details")

    def test_email_matches_plus_addressing(self) -> None:
        assert _matches(EMAIL, "user+tag@subdomain.example.org")

    def test_email_no_match_plain_text(self) -> None:
        assert not _matches(EMAIL, "No email here at all")

    def test_phone_matches_us_format(self) -> None:
        assert _matches(PHONE, "Call us at 555-010-1234")

    def test_phone_matches_parenthesis_format(self) -> None:
        assert _matches(PHONE, "(800) 555-0199")

    def test_phone_no_match_short_number(self) -> None:
        assert not _matches(PHONE, "Call 123")

    def test_phone_international_matches_plus_prefix(self) -> None:
        assert _matches(PHONE_INTERNATIONAL, "+44 20 7946 0958")

    def test_credit_card_visa_matches(self) -> None:
        # Synthetic Visa-format: starts with 4, 16 digits.
        assert _matches(CREDIT_CARD, "4111111111111111")

    def test_credit_card_amex_matches(self) -> None:
        # Synthetic Amex: starts with 37, 15 digits.
        assert _matches(CREDIT_CARD, "371449635398431")

    def test_ipv4_matches_loopback(self) -> None:
        assert _matches(IPV4_ADDRESS, "Connecting to 127.0.0.1")

    def test_ipv4_matches_private_range(self) -> None:
        assert _matches(IPV4_ADDRESS, "Server at 192.168.1.100")

    def test_ipv4_no_match_invalid(self) -> None:
        assert not _matches(IPV4_ADDRESS, "999.999.999.999")

    def test_date_of_birth_matches_keyword(self) -> None:
        assert _matches(DATE_OF_BIRTH, "DOB: 01/01/1990")

    def test_date_of_birth_no_match_without_keyword(self) -> None:
        assert not _matches(DATE_OF_BIRTH, "01/01/1990")

    def test_full_name_matches_with_keyword(self) -> None:
        assert _matches(FULL_NAME, "Patient: John Michael Smith")

    def test_common_patterns_list_length(self) -> None:
        assert len(COMMON_PATTERNS) >= 5


# ---------------------------------------------------------------------------
# US patterns
# ---------------------------------------------------------------------------


class TestUsPatterns:
    def test_ssn_matches_synthetic_format(self) -> None:
        # Synthetic SSN — does NOT match 000, 666, 9xx prefix or 00/0000 groups.
        assert _matches(SSN, "123-45-6789")

    def test_ssn_no_match_invalid_prefix_000(self) -> None:
        assert not _matches(SSN, "000-45-6789")

    def test_ssn_no_match_invalid_prefix_666(self) -> None:
        assert not _matches(SSN, "666-45-6789")

    def test_ssn_no_match_invalid_middle_00(self) -> None:
        assert not _matches(SSN, "123-00-6789")

    def test_ssn_no_match_invalid_last_0000(self) -> None:
        assert not _matches(SSN, "123-45-0000")

    def test_ein_matches_format(self) -> None:
        # Synthetic EIN: 12-3456789
        assert _matches(EIN, "EIN: 12-3456789")

    def test_us_zip_matches_five_digit(self) -> None:
        assert _matches(US_ZIP, "ZIP 90210")

    def test_us_zip_matches_zip_plus_four(self) -> None:
        assert _matches(US_ZIP, "ZIP 90210-1234")

    def test_us_patterns_list_non_empty(self) -> None:
        assert len(US_PATTERNS) >= 5


# ---------------------------------------------------------------------------
# EU patterns
# ---------------------------------------------------------------------------


class TestEuPatterns:
    def test_iban_matches_gb_format(self) -> None:
        # Synthetic UK IBAN: GB29 NWBK 6016 1331 9268 19
        assert _matches(IBAN, "IBAN: GB29NWBK60161331926819")

    def test_iban_matches_de_format(self) -> None:
        # Synthetic DE IBAN: DE02200400300628435040
        assert _matches(IBAN, "Account: DE02200400300628435040")

    def test_iban_no_match_plain_digits(self) -> None:
        assert not _matches(IBAN, "12345678901234")

    def test_eu_vat_matches_de_prefix(self) -> None:
        assert _matches(EU_VAT, "VAT: DE123456789")

    def test_eu_vat_matches_fr_prefix(self) -> None:
        assert _matches(EU_VAT, "FR12345678901")

    def test_bic_matches_format(self) -> None:
        # Synthetic BIC/SWIFT: DEUTDEDB (Deutsche Bank)
        assert _matches(BIC, "BIC: DEUTDEDB")

    def test_eu_patterns_list_non_empty(self) -> None:
        assert len(EU_PATTERNS) >= 4


# ---------------------------------------------------------------------------
# India patterns
# ---------------------------------------------------------------------------


class TestIndiaPatterns:
    def test_aadhaar_matches_12_digit_synthetic(self) -> None:
        # Synthetic Aadhaar: starts 2-9, 12 digits total.
        assert _matches(AADHAAR, "Aadhaar: 2345 6789 0123")

    def test_aadhaar_no_match_starts_with_0(self) -> None:
        assert not _matches(AADHAAR, "0123 4567 8901")

    def test_aadhaar_no_match_starts_with_1(self) -> None:
        assert not _matches(AADHAAR, "1234 5678 9012")

    def test_pan_matches_format(self) -> None:
        # Synthetic PAN: ABCDE1234F
        assert _matches(PAN, "PAN: ABCDE1234F")

    def test_pan_no_match_wrong_format(self) -> None:
        assert not _matches(PAN, "ABCDE12345")

    def test_voter_id_matches_format(self) -> None:
        # Synthetic Voter ID: 3 letters + 7 digits
        assert _matches(VOTER_ID, "Voter ID: ABC1234567")

    def test_gstin_matches_format(self) -> None:
        # Synthetic GSTIN: 22ABCDE1234F1Z5
        assert _matches(GSTIN, "GSTIN: 22ABCDE1234F1Z5")

    def test_in_mobile_matches_format(self) -> None:
        # Synthetic Indian mobile: starts 6-9, 10 digits.
        assert _matches(IN_MOBILE, "Mobile: 9876543210")

    def test_in_mobile_with_country_code(self) -> None:
        assert _matches(IN_MOBILE, "+91-9876543210")

    def test_india_patterns_list_non_empty(self) -> None:
        assert len(INDIA_PATTERNS) >= 5
