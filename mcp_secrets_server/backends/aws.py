"""
AWS Secrets Manager backend.

Requires:
    pip install boto3

Configure via environment:
    AWS_REGION=us-east-1
    AWS_ACCESS_KEY_ID=...
    AWS_SECRET_ACCESS_KEY=...

Or use IAM instance roles / ECS task roles — boto3 picks those up automatically.
"""

import json
import logging
from .base import SecretBackendBase
from ..config import secrets_settings

logger = logging.getLogger("mcp_secrets.aws")


class AWSSecretsBackend(SecretBackendBase):

    def __init__(self):
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError:
            raise RuntimeError(
                "boto3 is required for AWS backend. Install with: pip install boto3"
            )

        if not secrets_settings.AWS_REGION:
            raise RuntimeError("AWS_REGION must be set for AWS Secrets Manager backend")

        kwargs = {"region_name": secrets_settings.AWS_REGION}
        if secrets_settings.AWS_ACCESS_KEY_ID:
            kwargs["aws_access_key_id"] = secrets_settings.AWS_ACCESS_KEY_ID
            kwargs["aws_secret_access_key"] = secrets_settings.AWS_SECRET_ACCESS_KEY

        self._client = boto3.client("secretsmanager", **kwargs)
        return self._client

    async def get_secret(self, path: str) -> str:
        """
        Retrieve a secret from AWS Secrets Manager.
        path = the secret name or ARN.
        If the secret value is JSON, extracts the 'value' key.
        Otherwise returns the raw string.
        """
        client = self._get_client()
        try:
            response = client.get_secret_value(SecretId=path)
            raw = response.get("SecretString") or response.get("SecretBinary", b"").decode()

            # Try JSON first — secrets stored as {"value": "..."} or {"key": "..."}
            try:
                data = json.loads(raw)
                return data.get("value") or raw
            except (json.JSONDecodeError, AttributeError):
                return raw

        except Exception as exc:
            logger.error("AWS get_secret failed for %s: %s", path, exc)
            raise ValueError(f"Could not retrieve secret from AWS: {exc}") from exc

    async def put_secret(self, path: str, value: str) -> None:
        client = self._get_client()
        secret_string = json.dumps({"value": value})
        try:
            try:
                client.put_secret_value(SecretId=path, SecretString=secret_string)
            except client.exceptions.ResourceNotFoundException:
                client.create_secret(Name=path, SecretString=secret_string)
        except Exception as exc:
            logger.error("AWS put_secret failed for %s: %s", path, exc)
            raise ValueError(f"Could not write secret to AWS: {exc}") from exc

    async def delete_secret(self, path: str) -> None:
        client = self._get_client()
        try:
            client.delete_secret(SecretId=path, ForceDeleteWithoutRecovery=False)
        except Exception as exc:
            logger.error("AWS delete_secret failed for %s: %s", path, exc)

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            client.list_secrets(MaxResults=1)
            return True
        except Exception:
            return False


aws_backend = AWSSecretsBackend()
