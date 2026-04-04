from abc import ABC, abstractmethod
from typing import List, Tuple


class DetectorBase(ABC):
    """
    Base class for all PII detectors.
    Each detector handles one or more PIITypes and returns
    a list of (matched_string, pii_type) tuples for a given text.
    """

    @property
    @abstractmethod
    def pii_types(self) -> List[str]:
        """List of PIIType values this detector handles."""
        ...

    @abstractmethod
    def scan(self, text: str) -> List[Tuple[str, str]]:
        """
        Scan text and return list of (matched_value, pii_type) tuples.
        May return multiple hits if text contains multiple PII values.
        """
        ...
