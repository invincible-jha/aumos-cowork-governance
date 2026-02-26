"""EU-specific PII patterns.

Covers identifiers relevant under GDPR and EU financial regulations
including IBAN, EU VAT numbers, and EU passport formats.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# International Bank Account Number (IBAN)
# ISO 13616 — covers all EU/EEA member state formats
# ---------------------------------------------------------------------------
IBAN = (
    "eu_iban",
    re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b",
    ),
)

# ---------------------------------------------------------------------------
# EU VAT registration numbers — common format prefix CC + digits
# ---------------------------------------------------------------------------
EU_VAT = (
    "eu_vat_number",
    re.compile(
        r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT"
        r"|NL|PL|PT|RO|SE|SI|SK)[0-9A-Za-z]{2,12}\b",
    ),
)

# ---------------------------------------------------------------------------
# EU passport numbers — country code + 8-9 alphanumeric characters
# ---------------------------------------------------------------------------
EU_PASSPORT = (
    "eu_passport",
    re.compile(
        r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT"
        r"|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{7,9}\b",
    ),
)

# ---------------------------------------------------------------------------
# National identity card numbers (generic EU format heuristic)
# ---------------------------------------------------------------------------
EU_NATIONAL_ID = (
    "eu_national_id",
    re.compile(
        r"\b(?:NID|National ID|ID No)[:\s]*[A-Z0-9]{6,12}\b",
        re.IGNORECASE,
    ),
)

# ---------------------------------------------------------------------------
# German personal identification number (Steuerliche Identifikationsnummer)
# ---------------------------------------------------------------------------
DE_STEUER_ID = (
    "de_steuer_id",
    re.compile(
        r"\b[1-9]\d{10}\b",
    ),
)

# ---------------------------------------------------------------------------
# French INSEE / NIR (Social Security Number)
# ---------------------------------------------------------------------------
FR_INSEE = (
    "fr_insee",
    re.compile(
        r"\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}(?:0[1-9]|[1-9]\d|9[0-9])\d{3}\d{2}\b",
    ),
)

# ---------------------------------------------------------------------------
# SWIFT / BIC code (often paired with IBAN)
# ---------------------------------------------------------------------------
BIC = (
    "swift_bic",
    re.compile(
        r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
    ),
)

# ---------------------------------------------------------------------------
# Exported collection
# ---------------------------------------------------------------------------
EU_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    IBAN,
    EU_VAT,
    EU_PASSPORT,
    EU_NATIONAL_ID,
    DE_STEUER_ID,
    FR_INSEE,
    BIC,
]
