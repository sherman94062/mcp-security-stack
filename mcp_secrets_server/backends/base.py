"""
Abstract base class for secret backends.
All backends implement the same interface so the rest of the server
is backend-agnostic.
"""

from abc import ABC, abstractmethod
from typing import Optional


class SecretBackendBase(ABC):

    @abstractmethod
    async def get_secret(self, path: str) -> str:
        """
        Retrieve a secret value from the backend by its path/name.
        Raises ValueError if the secret does not exist.
        """
        ...

    @abstractmethod
    async def put_secret(self, path: str, value: str) -> None:
        """
        Create or update a secret value in the backend.
        """
        ...

    @abstractmethod
    async def delete_secret(self, path: str) -> None:
        """
        Delete a secret from the backend.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the backend is reachable."""
        ...
