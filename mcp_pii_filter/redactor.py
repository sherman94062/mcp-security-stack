"""
Applies redaction strategies to detected PII values.

REDACT → [REDACTED:EMAIL]
MASK   → j***@gmail.com  |  ****-****-****-1234  |  +1-***-***-7890
HASH   → [HASH:a3f2c1...]  (consistent SHA-256 token for correlation)
FLAG   → value unchanged, detection metadata returned separately
"""

import hashlib
import re
import json
from typing import Any, Dict, List, Tuple, Set, Optional

from .models import Detection, PIIType, RedactionStrategy
from .detectors import scan_text


def _redact_label(pii_type: str) -> str:
    return f"[REDACTED:{pii_type}]"


def _mask_value(value: str, pii_type: str) -> str:
    """Apply type-specific masking."""
    if pii_type == "EMAIL":
        parts = value.split("@")
        if len(parts) == 2:
            local = parts[0]
            masked_local = local[0] + "***" if len(local) > 1 else "***"
            return f"{masked_local}@{parts[1]}"
        return "***@***.***"

    if pii_type == "CREDIT_CARD":
        digits = re.sub(r'[ \-]', '', value)
        return f"****-****-****-{digits[-4:]}"

    if pii_type == "PHONE":
        digits = re.sub(r'\D', '', value)
        if len(digits) >= 7:
            return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
        return "***-***-****"

    if pii_type == "SSN":
        return "***-**-" + re.sub(r'\D', '', value)[-4:]

    if pii_type in ("IBAN", "BANK_ACCOUNT"):
        clean = re.sub(r'[ \-]', '', value)
        return clean[:4] + "*" * max(0, len(clean) - 8) + clean[-4:]

    if pii_type in ("CRYPTO_BTC", "CRYPTO_ETH", "CRYPTO_SOL"):
        return value[:6] + "..." + value[-4:]

    if pii_type == "IP_ADDRESS":
        parts = value.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***.***"
        return "***:***:***:***"

    # Default: show first 2 chars, mask the rest
    if len(value) > 4:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return "*" * len(value)


def _hash_value(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"[HASH:{digest}]"


def redact_string(
    text: str,
    enabled_types: List[str],
    strategy: str,
    field_allowlist: Optional[Set[str]] = None,
) -> Tuple[str, List[Tuple[str, str, str]]]:
    """
    Scan and redact a single string value.
    Returns (redacted_text, [(original, pii_type, replacement), ...]).
    """
    hits = scan_text(text, enabled_types)
    detections = []
    result = text

    for original, pii_type in hits:
        if strategy == RedactionStrategy.FLAG:
            replacement = original  # Leave in place
        elif strategy == RedactionStrategy.MASK:
            replacement = _mask_value(original, pii_type)
        elif strategy == RedactionStrategy.HASH:
            replacement = _hash_value(original)
        else:  # REDACT (default)
            replacement = _redact_label(pii_type)

        detections.append((original, pii_type, replacement))
        if strategy != RedactionStrategy.FLAG:
            result = result.replace(original, replacement)

    return result, detections


def redact_payload(
    payload: Any,
    enabled_types: List[str],
    strategy: str,
    field_allowlist: Optional[Set[str]] = None,
    _current_path: str = "",
) -> Tuple[Any, List[Detection]]:
    """
    Recursively walk a JSON-serialisable payload and redact PII in all string values.
    Returns (clean_payload, list_of_Detection).
    """
    all_detections: List[Detection] = []

    if isinstance(payload, dict):
        clean = {}
        for key, value in payload.items():
            field_path = f"{_current_path}.{key}" if _current_path else key
            # Skip allowlisted fields
            if field_allowlist and (key in field_allowlist or field_path in field_allowlist):
                clean[key] = value
                continue
            clean_value, dets = redact_payload(
                value, enabled_types, strategy, field_allowlist, field_path
            )
            clean[key] = clean_value
            all_detections.extend(dets)
        return clean, all_detections

    elif isinstance(payload, list):
        clean = []
        for i, item in enumerate(payload):
            field_path = f"{_current_path}[{i}]"
            clean_item, dets = redact_payload(
                item, enabled_types, strategy, field_allowlist, field_path
            )
            clean.append(clean_item)
            all_detections.extend(dets)
        return clean, all_detections

    elif isinstance(payload, str):
        clean_text, raw_detections = redact_string(payload, enabled_types, strategy)
        for original, pii_type, replacement in raw_detections:
            all_detections.append(Detection(
                pii_type=PIIType(pii_type),
                field_path=_current_path or "root",
                original=original if strategy == RedactionStrategy.FLAG else None,
                redacted=replacement,
                strategy=RedactionStrategy(strategy),
            ))
        return clean_text, all_detections

    else:
        # Numbers, booleans, None — pass through unchanged
        return payload, []
