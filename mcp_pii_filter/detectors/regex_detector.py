"""
Regex-based detectors for common PII types.
No ML dependencies — fast, deterministic, auditable.
"""

import re
from typing import List, Tuple
from .base import DetectorBase


# ── Email ──────────────────────────────────────────────────────────────────────

class EmailDetector(DetectorBase):
    pii_types = ["EMAIL"]
    _pattern = re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "EMAIL") for m in self._pattern.finditer(text)]


# ── Phone ──────────────────────────────────────────────────────────────────────

class PhoneDetector(DetectorBase):
    pii_types = ["PHONE"]
    # Matches international and domestic formats
    _pattern = re.compile(
        r'\b(?:\+?1[-.\s]?)?'
        r'(?:\(?\d{3}\)?[-.\s]?)'
        r'\d{3}[-.\s]?\d{4}\b'
        r'|'
        r'\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{4,10}\b'
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group().strip(), "PHONE") for m in self._pattern.finditer(text)]


# ── Credit / Debit Cards (with Luhn check) ─────────────────────────────────────

class CreditCardDetector(DetectorBase):
    pii_types = ["CREDIT_CARD"]
    # 13-19 digits, optionally separated by spaces or dashes
    _pattern = re.compile(r'\b(?:\d[ \-]?){13,19}\b')

    @staticmethod
    def _luhn(number: str) -> bool:
        digits = [int(c) for c in number if c.isdigit()]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        doubled = [d * 2 if d * 2 < 10 else d * 2 - 9 for d in even]
        return (sum(odd) + sum(doubled)) % 10 == 0

    def scan(self, text: str) -> List[Tuple[str, str]]:
        results = []
        for m in self._pattern.finditer(text):
            raw = m.group()
            digits_only = re.sub(r'[ \-]', '', raw)
            if len(digits_only) >= 13 and self._luhn(digits_only):
                results.append((raw, "CREDIT_CARD"))
        return results


# ── SSN (US Social Security Number) ───────────────────────────────────────────

class SSNDetector(DetectorBase):
    pii_types = ["SSN"]
    _pattern = re.compile(
        r'\b(?!000|666|9\d{2})\d{3}'   # Area: not 000, 666, or 900-999
        r'[-\s]?'
        r'(?!00)\d{2}'                  # Group: not 00
        r'[-\s]?'
        r'(?!0000)\d{4}\b'             # Serial: not 0000
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "SSN") for m in self._pattern.finditer(text)]


# ── IBAN ───────────────────────────────────────────────────────────────────────

class IBANDetector(DetectorBase):
    pii_types = ["IBAN"]
    # ISO 13616: 2-letter country code + 2 check digits + up to 30 alphanumeric
    _pattern = re.compile(
        r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "IBAN") for m in self._pattern.finditer(text)]


# ── US Bank Account / Routing Numbers ─────────────────────────────────────────

class BankAccountDetector(DetectorBase):
    pii_types = ["BANK_ACCOUNT"]
    # US routing (9 digits) or account (6-17 digits) in context
    _routing = re.compile(r'\brouting[:\s#]*(\d{9})\b', re.IGNORECASE)
    _account = re.compile(r'\baccount[:\s#]*(\d{6,17})\b', re.IGNORECASE)

    def scan(self, text: str) -> List[Tuple[str, str]]:
        results = []
        for m in self._routing.finditer(text):
            results.append((m.group(), "BANK_ACCOUNT"))
        for m in self._account.finditer(text):
            results.append((m.group(), "BANK_ACCOUNT"))
        return results


# ── IP Address ─────────────────────────────────────────────────────────────────

class IPAddressDetector(DetectorBase):
    pii_types = ["IP_ADDRESS"]
    _ipv4 = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    _ipv6 = re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        r'|'
        r'\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b'
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        results = []
        for m in self._ipv4.finditer(text):
            # Skip private ranges that aren't truly PII in most contexts
            ip = m.group()
            if not (ip.startswith("127.") or ip.startswith("192.168.")
                    or ip.startswith("10.") or ip == "0.0.0.0"):
                results.append((ip, "IP_ADDRESS"))
        for m in self._ipv6.finditer(text):
            results.append((m.group(), "IP_ADDRESS"))
        return results


# ── Date of Birth ──────────────────────────────────────────────────────────────

class DateOfBirthDetector(DetectorBase):
    pii_types = ["DATE_OF_BIRTH"]
    # Looks for DOB in context: "dob:", "date_of_birth:", "born:", "birth_date:"
    _pattern = re.compile(
        r'(?:dob|date.of.birth|birth.?date|born)[:\s]*'
        r'(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}'
        r'|\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2})',
        re.IGNORECASE
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "DATE_OF_BIRTH") for m in self._pattern.finditer(text)]


# ── Passport Numbers ───────────────────────────────────────────────────────────

class PassportDetector(DetectorBase):
    pii_types = ["PASSPORT"]
    # Context-aware: "passport:", "passport_no:", followed by common formats
    _pattern = re.compile(
        r'(?:passport|passport.?(?:no|number|num))[:\s#]*([A-Z]{1,2}\d{6,9})',
        re.IGNORECASE
    )
    # Also catch standalone patterns (less precise without context)
    _standalone = re.compile(r'\b[A-Z]{2}\d{7}\b')

    def scan(self, text: str) -> List[Tuple[str, str]]:
        results = []
        seen = set()
        for m in self._pattern.finditer(text):
            val = m.group()
            if val not in seen:
                seen.add(val)
                results.append((val, "PASSPORT"))
        for m in self._standalone.finditer(text):
            val = m.group()
            if val not in seen:
                seen.add(val)
                results.append((val, "PASSPORT"))
        return results


# ── National ID (generic) ──────────────────────────────────────────────────────

class NationalIDDetector(DetectorBase):
    pii_types = ["NATIONAL_ID"]
    _pattern = re.compile(
        r'(?:national.?id|nin|nino|tax.?id|nid)[:\s#]*([A-Z0-9]{6,12})',
        re.IGNORECASE
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "NATIONAL_ID") for m in self._pattern.finditer(text)]


# ── URL with embedded PII (tokens, emails in query strings) ───────────────────

class URLWithPIIDetector(DetectorBase):
    pii_types = ["URL_WITH_PII"]
    # URLs containing email-like params or long tokens in query strings
    _pattern = re.compile(
        r'https?://[^\s]+[?&]'
        r'(?:email|token|key|auth|password|secret|ssn|account)[=][^\s&"\']+',
        re.IGNORECASE
    )

    def scan(self, text: str) -> List[Tuple[str, str]]:
        return [(m.group(), "URL_WITH_PII") for m in self._pattern.finditer(text)]
