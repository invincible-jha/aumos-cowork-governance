"""Universal PII patterns applicable across all jurisdictions.

Patterns are compiled regular expressions paired with a human-readable
label describing the PII type they detect.

Each entry is a tuple of ``(label, compiled_pattern)``.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Email addresses
# ---------------------------------------------------------------------------
EMAIL = (
    "email_address",
    re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        re.IGNORECASE,
    ),
)

# ---------------------------------------------------------------------------
# Phone numbers — loose international format
# ---------------------------------------------------------------------------
PHONE = (
    "phone_number",
    re.compile(
        r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b",
    ),
)

PHONE_INTERNATIONAL = (
    "phone_number_international",
    re.compile(
        r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
    ),
)

# ---------------------------------------------------------------------------
# Payment card numbers — major schemes (Visa, MC, Amex, Discover)
# ---------------------------------------------------------------------------
CREDIT_CARD = (
    "credit_card_number",
    re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?"         # Visa
        r"|5[1-5][0-9]{14}"                       # MasterCard
        r"|3[47][0-9]{13}"                        # Amex
        r"|6(?:011|5[0-9]{2})[0-9]{12}"          # Discover
        r"|3(?:0[0-5]|[68][0-9])[0-9]{11}"       # Diners Club
        r"|(?:2131|1800|35\d{3})\d{11})\b",      # JCB
    ),
)

# ---------------------------------------------------------------------------
# IP addresses (IPv4)
# ---------------------------------------------------------------------------
IPV4_ADDRESS = (
    "ipv4_address",
    re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    ),
)

# ---------------------------------------------------------------------------
# Date of birth patterns
# ---------------------------------------------------------------------------
DATE_OF_BIRTH = (
    "date_of_birth",
    re.compile(
        r"\b(?:DOB|Date of Birth|Birth(?:day|date)?)[:\s]+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
        re.IGNORECASE,
    ),
)

# ---------------------------------------------------------------------------
# Full name patterns (heuristic — two or three capitalised words)
# ---------------------------------------------------------------------------
FULL_NAME = (
    "full_name",
    re.compile(
        r"\b(?:Name|Patient|Client|Subscriber)[:\s]+([A-Z][a-z]+ ){1,2}[A-Z][a-z]+\b",
        re.IGNORECASE,
    ),
)

# ---------------------------------------------------------------------------
# Exported collection
# ---------------------------------------------------------------------------
COMMON_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    EMAIL,
    PHONE,
    PHONE_INTERNATIONAL,
    CREDIT_CARD,
    IPV4_ADDRESS,
    DATE_OF_BIRTH,
    FULL_NAME,
]
