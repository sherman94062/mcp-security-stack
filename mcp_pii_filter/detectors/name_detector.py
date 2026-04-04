"""
Person name detector using context-aware heuristics.
No ML dependency — uses field name signals and capitalisation patterns.
Tuned for remittance/fintech payloads where names appear in predictable fields.
"""

import re
from typing import List, Tuple
from .base import DetectorBase


# Field names that commonly contain person names in fintech APIs
NAME_FIELD_SIGNALS = re.compile(
    r'(?:sender|recipient|receiver|beneficiary|customer|payee|payer|'
    r'account.?holder|full.?name|first.?name|last.?name|given.?name|'
    r'family.?name|middle.?name|contact.?name|authorized|signatory)',
    re.IGNORECASE
)

# A "name-like" value: 2-4 capitalised words, each 2-30 chars, no digits
NAME_VALUE_PATTERN = re.compile(
    r'\b([A-Z][a-z]{1,29})(?:\s+(?:van|de|di|del|la|le|al|el|bin|binti|'
    r'[A-Z][a-z]{1,29})){1,3}\b'
)

# Common non-name proper nouns to exclude (reduce false positives)
EXCLUSIONS = {
    "United States", "United Kingdom", "New York", "Los Angeles",
    "San Francisco", "South Africa", "Mobile Money", "Bank Transfer",
    "Wire Transfer", "Swift Code", "Sort Code", "Account Number",
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    "January", "February", "March", "April", "June", "July",
    "August", "September", "October", "November", "December",
    "True", "False", "None", "Null",
}


class PersonNameDetector(DetectorBase):
    pii_types = ["PERSON_NAME"]

    def scan(self, text: str) -> List[Tuple[str, str]]:
        """
        Find person names using two strategies:
        1. Field-name context: values adjacent to name-field keywords
        2. Structural pattern: capitalised word sequences in plain text
        """
        results = []
        seen = set()

        # Strategy 1: field-name context (high precision)
        # Looks for patterns like: "sender_name": "John Smith"
        field_pattern = re.compile(
            r'(?:' + NAME_FIELD_SIGNALS.pattern + r')'
            r'["\']?\s*[:=]\s*["\']?'
            r'([A-Z][a-z]{1,29}(?:\s+[A-Z][a-z]{1,29}){1,3})',
            re.IGNORECASE
        )
        for m in field_pattern.finditer(text):
            name = m.group(1).strip() if m.lastindex else m.group().strip()
            if name not in EXCLUSIONS and name not in seen:
                seen.add(name)
                results.append((name, "PERSON_NAME"))

        # Strategy 2: structural name pattern (lower precision, use carefully)
        for m in NAME_VALUE_PATTERN.finditer(text):
            name = m.group().strip()
            if name not in EXCLUSIONS and name not in seen and len(name.split()) >= 2:
                seen.add(name)
                results.append((name, "PERSON_NAME"))

        return results
