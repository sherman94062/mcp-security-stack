from typing import List, Dict, Tuple
from .base import DetectorBase
from .regex_detector import (
    EmailDetector, PhoneDetector, CreditCardDetector, SSNDetector,
    IBANDetector, BankAccountDetector, IPAddressDetector,
    DateOfBirthDetector, PassportDetector, NationalIDDetector,
    URLWithPIIDetector,
)
from .crypto_detector import BitcoinDetector, EthereumDetector, SolanaDetector
from .name_detector import PersonNameDetector


# All detectors, instantiated once
_ALL_DETECTORS: List[DetectorBase] = [
    EmailDetector(),
    PhoneDetector(),
    CreditCardDetector(),
    SSNDetector(),
    IBANDetector(),
    BankAccountDetector(),
    IPAddressDetector(),
    DateOfBirthDetector(),
    PassportDetector(),
    NationalIDDetector(),
    URLWithPIIDetector(),
    BitcoinDetector(),
    EthereumDetector(),
    SolanaDetector(),
    PersonNameDetector(),
]

# Map from PIIType string → detector
_TYPE_TO_DETECTOR: Dict[str, DetectorBase] = {}
for det in _ALL_DETECTORS:
    for ptype in det.pii_types:
        _TYPE_TO_DETECTOR[ptype] = det


def get_detectors(enabled_types: List[str]) -> List[DetectorBase]:
    """Return detectors for the requested PII types (deduped)."""
    seen_ids = set()
    result = []
    for ptype in enabled_types:
        det = _TYPE_TO_DETECTOR.get(ptype)
        if det and id(det) not in seen_ids:
            seen_ids.add(id(det))
            result.append(det)
    return result


def scan_text(text: str, enabled_types: List[str]) -> List[Tuple[str, str]]:
    """
    Run all enabled detectors against a text string.
    Returns list of (matched_value, pii_type) tuples.
    Deduplicates overlapping matches.
    """
    hits = []
    seen_values = set()
    for det in get_detectors(enabled_types):
        for value, ptype in det.scan(text):
            if value not in seen_values:
                seen_values.add(value)
                hits.append((value, ptype))
    return hits
