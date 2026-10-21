"""HTTP client for the OPAQUE sidecar (cmd/opaque-sidecar in the CLI repo).

No OPAQUE math happens here. Each call forwards opaque blobs and returns the
sidecar's answer. Every failure path raises: callers must refuse to authenticate
rather than fall back to password.
"""

import base64
import logging

import requests
from django.conf import settings

logger = logging.getLogger("apps.accounts")

DEFAULT_TIMEOUT_SECONDS = 5


class SidecarError(Exception):
    """The sidecar could not answer. Treat as an outage, never as a soft failure."""


class Sidecar:
    def __init__(self) -> None:
        url = getattr(settings, "OPAQUE_SIDECAR_URL", "") or ""
        token = getattr(settings, "OPAQUE_SIDECAR_TOKEN", "") or ""
        if not url or not token:
            raise SidecarError("OPAQUE sidecar is not configured")
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = getattr(settings, "OPAQUE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )

    # -- encoding -------------------------------------------------------

    @staticmethod
    def encode_base64(raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def decode_base64(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        try:
            return base64.b64decode(value + padding, validate=True)
        except ValueError as exc:
            raise SidecarError(f"invalid base64 from client: {exc}") from exc

    # -- endpoints ------------------------------------------------------

    def register_start(self, reg_request: str, credential_id: str) -> dict:
        return self._post(
            "/v1/register/response",
            {"reg_request": reg_request, "credential_id": credential_id},
        )

    def register_finish(self, reg_record: str, credential_id: str) -> dict:
        return self._post(
            "/v1/register/finish",
            {"reg_record": reg_record, "credential_id": credential_id},
        )

    def login_start(self, ke1: str, record: str, credential_id: str) -> dict:
        return self._post(
            "/v1/login/start",
            {"ke1": ke1, "record": record, "credential_id": credential_id},
        )

    def login_finish(self, ke3: str, server_state: str, credential_id: str) -> dict:
        return self._post(
            "/v1/login/finish",
            {"ke3": ke3, "server_state": server_state, "credential_id": credential_id},
        )

    def check_health(self) -> bool:
        try:
            response = self._session.get(f"{self.url}/healthz", timeout=2)
        except requests.RequestException:
            return False
        return response.status_code == 200 and response.text.strip() == "ok"

    # -- transport ------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.url}{path}"
        try:
            response = self._session.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.error("OPAQUE sidecar unreachable at %s: %s", url, exc)
            raise SidecarError(f"OPAQUE sidecar unreachable: {exc}") from exc

        if response.status_code == 401:
            logger.error("OPAQUE sidecar rejected the token at %s", url)
            raise SidecarError("OPAQUE sidecar rejected the bearer token")
        if response.status_code != 200:
            logger.error("OPAQUE sidecar returned %s at %s: %s", response.status_code, url, response.text[:200])
            raise SidecarError(f"OPAQUE sidecar returned {response.status_code}")

        try:
            return response.json()
        except ValueError as exc:
            logger.error("OPAQUE sidecar returned non-JSON at %s", url)
            raise SidecarError("OPAQUE sidecar returned a non-JSON body") from exc


def make_sidecar() -> Sidecar:
    return Sidecar()
