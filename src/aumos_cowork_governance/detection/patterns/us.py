"""US-specific PII patterns.

Covers identifiers regulated by US federal and state law including
the Social Security Act, HIPAA, and state DMV regulations.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Social Security Number
# ---------------------------------------------------------------------------
SSN = (
    "us_ssn",
    re.compile(
        r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
    ),
)

# ---------------------------------------------------------------------------
# Employer Identification Number (EIN / Federal Tax ID)
# ---------------------------------------------------------------------------
EIN = (
    "us_ein",
    re.compile(
        r"\b\d{2}-\d{7}\b",
    ),
)

# ---------------------------------------------------------------------------
# Individual Taxpayer Identification Number (ITIN)
# ---------------------------------------------------------------------------
ITIN = (
    "us_itin",
    re.compile(
        r"\b9\d{2}[-\s]?[7-9]\d[-\s]?\d{4}\b",
    ),
)

# ---------------------------------------------------------------------------
# US Passport number (generic format)
# ---------------------------------------------------------------------------
US_PASSPORT = (
    "us_passport",
    re.compile(
        r"\b[A-Z]{1,2}\d{6,9}\b",
    ),
)

# ---------------------------------------------------------------------------
# US Driver's licence — heuristic (varies widely by state)
# ---------------------------------------------------------------------------
US_DRIVERS_LICENSE = (
    "us_drivers_license",
    re.compile(
        r"\b(?:[A-Z]\d{7}|\d{7,9}|[A-Z]{1,2}\d{6,8})\b",
    ),
)

# ---------------------------------------------------------------------------
# Medicare Beneficiary Identifier (MBI) — 11-character alphanumeric
# ---------------------------------------------------------------------------
MEDICARE_MBI = (
    "us_medicare_mbi",
    re.compile(
        r"\b[1-9][AC-HJ-NP-RT-Y][AC-HJ-NP-RT-Y0-9]\d[AC-HJ-NP-RT-Y][AC-HJ-NP-RT-Y0-9]\d[AC-HJ-NP-RT-Y]{2}\d{2}\b",
    ),
)

# ---------------------------------------------------------------------------
# National Provider Identifier (NPI) — 10 digits
# ---------------------------------------------------------------------------
NPI = (
    "us_npi",
    re.compile(
        r"\bNPI[:\s]*\d{10}\b",
        re.IGNORECASE,
    ),
)

# ---------------------------------------------------------------------------
# US ZIP code
# ---------------------------------------------------------------------------
US_ZIP = (
    "us_zip_code",
    re.compile(
        r"\b\d{5}(?:-\d{4})?\b",
    ),
)

# ---------------------------------------------------------------------------
# Exported collection
# ---------------------------------------------------------------------------
US_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    SSN,
    EIN,
    ITIN,
    US_PASSPORT,
    US_DRIVERS_LICENSE,
    MEDICARE_MBI,
    NPI,
    US_ZIP,
]
