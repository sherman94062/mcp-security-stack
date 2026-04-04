from .base import SecretBackendBase
from .local import local_backend
from .vault import vault_backend
from .aws import aws_backend
from .gcp import gcp_backend
from ..models import SecretBackend


def get_backend(backend_type: str) -> SecretBackendBase:
    """Factory: return the appropriate backend instance."""
    if backend_type == SecretBackend.LOCAL:
        return local_backend
    elif backend_type == SecretBackend.VAULT:
        return vault_backend
    elif backend_type == SecretBackend.AWS:
        return aws_backend
    elif backend_type == SecretBackend.GCP:
        return gcp_backend
    else:
        raise ValueError(f"Unknown secret backend: {backend_type}")
