"""India-specific PII patterns.

Covers identifiers regulated under India's Digital Personal Data
Protection Act (DPDPA) and related regulations.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Aadhaar number — 12 digits, optionally space/hyphen separated in groups
# ---------------------------------------------------------------------------
AADHAAR = (
    "in_aadhaar",
    re.compile(
        r"\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b",
    ),
)

# ---------------------------------------------------------------------------
# Permanent Account Number (PAN) — income tax identifier
# Format: AAAAA9999A (5 letters, 4 digits, 1 letter)
# ---------------------------------------------------------------------------
PAN = (
    "in_pan",
    re.compile(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
    ),
)

# ---------------------------------------------------------------------------
# Indian passport number
# Format: letter + 7 digits
# ---------------------------------------------------------------------------
IN_PASSPORT = (
    "in_passport",
    re.compile(
        r"\b[A-Z]\d{7}\b",
    ),
)

# ---------------------------------------------------------------------------
# Voter ID (EPIC) — letter(s) + digits
# ---------------------------------------------------------------------------
VOTER_ID = (
    "in_voter_id",
    re.compile(
        r"\b[A-Z]{3}\d{7}\b",
    ),
)

# ---------------------------------------------------------------------------
# Driving licence — state code + year + sequence
# ---------------------------------------------------------------------------
IN_DRIVING_LICENCE = (
    "in_driving_licence",
    re.compile(
        r"\b[A-Z]{2}[-\s]?\d{2}[-\s]?\d{4}[-\s]?\d{7}\b",
    ),
)

# ---------------------------------------------------------------------------
# Goods and Services Tax Identification Number (GSTIN)
# Format: 2 digits state code + PAN + 1 digit entity + Z + 1 checksum
# ---------------------------------------------------------------------------
GSTIN = (
    "in_gstin",
    re.compile(
        r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
    ),
)

# ---------------------------------------------------------------------------
# Indian mobile number
# ---------------------------------------------------------------------------
IN_MOBILE = (
    "in_mobile",
    re.compile(
        r"\b(?:\+?91[-.\s]?)?[6-9]\d{9}\b",
    ),
)

# ---------------------------------------------------------------------------
# Exported collection
# ---------------------------------------------------------------------------
INDIA_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    AADHAAR,
    PAN,
    IN_PASSPORT,
    VOTER_ID,
    IN_DRIVING_LICENCE,
    GSTIN,
    IN_MOBILE,
]
