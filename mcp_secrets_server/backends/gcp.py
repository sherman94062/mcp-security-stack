"""
GCP Secret Manager backend.

Requires:
    pip install google-cloud-secret-manager

Configure via environment:
    GCP_PROJECT_ID=my-gcp-project
    GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

Or use Workload Identity on GKE — the client picks it up automatically.
"""

import logging
from .base import SecretBackendBase
from ..config import secrets_settings

logger = logging.getLogger("mcp_secrets.gcp")


class GCPSecretsBackend(SecretBackendBase):

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from google.cloud import secretmanager
        except ImportError:
            raise RuntimeError(
                "google-cloud-secret-manager is required for GCP backend. "
                "Install with: pip install google-cloud-secret-manager"
            )

        if not secrets_settings.GCP_PROJECT_ID:
            raise RuntimeError("GCP_PROJECT_ID must be set for GCP Secret Manager backend")

        self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    def _secret_name(self, path: str) -> str:
        project = secrets_settings.GCP_PROJECT_ID
        # path can be "payments/stripe-key" or just "stripe-key"
        # GCP names don't allow slashes, so normalise
        secret_id = path.replace("/", "--")
        return f"projects/{project}/secrets/{secret_id}/versions/latest"

    def _parent(self, path: str) -> str:
        project = secrets_settings.GCP_PROJECT_ID
        secret_id = path.replace("/", "--")
        return f"projects/{project}/secrets/{secret_id}"

    async def get_secret(self, path: str) -> str:
        client = self._get_client()
        name = self._secret_name(path)
        try:
            response = client.access_secret_version(request={"name": name})
            return response.payload.data.decode("utf-8")
        except Exception as exc:
            logger.error("GCP get_secret failed for %s: %s", path, exc)
            raise ValueError(f"Could not retrieve secret from GCP: {exc}") from exc

    async def put_secret(self, path: str, value: str) -> None:
        from google.cloud import secretmanager
        client = self._get_client()
        project = secrets_settings.GCP_PROJECT_ID
        secret_id = path.replace("/", "--")
        parent = f"projects/{project}"

        try:
            # Create if not exists
            try:
                client.create_secret(
                    request={
                        "parent": parent,
                        "secret_id": secret_id,
                        "secret": {"replication": {"automatic": {}}},
                    }
                )
            except Exception:
                pass  # Already exists

            # Add new version
            secret_name = f"projects/{project}/secrets/{secret_id}"
            client.add_secret_version(
                request={
                    "parent": secret_name,
                    "payload": {"data": value.encode("utf-8")},
                }
            )
        except Exception as exc:
            logger.error("GCP put_secret failed for %s: %s", path, exc)
            raise ValueError(f"Could not write secret to GCP: {exc}") from exc

    async def delete_secret(self, path: str) -> None:
        client = self._get_client()
        name = self._parent(path)
        try:
            client.delete_secret(request={"name": name})
        except Exception as exc:
            logger.error("GCP delete_secret failed for %s: %s", path, exc)

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            project = secrets_settings.GCP_PROJECT_ID
            list(client.list_secrets(
                request={"parent": f"projects/{project}", "page_size": 1}
            ))
            return True
        except Exception:
            return False


gcp_backend = GCPSecretsBackend()
