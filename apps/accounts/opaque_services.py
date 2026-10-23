"""OPAQUE account service.

All OPAQUE cryptography happens in the Go sidecar. This module forwards blobs,
owns the per-account method state, and fails closed: a sidecar outage is an
outage, never a password fallback.
"""

import logging
import secrets
from datetime import timedelta

from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.common.exceptions import OpaqueUnavailableError

from .opaque import SidecarError, make_sidecar

logger = logging.getLogger("apps.accounts")

CHALLENGE_TTL = timedelta(seconds=120)
CHALLENGE_WINDOW = timedelta(minutes=15)
MAX_CHALLENGES_PER_WINDOW = 10


class OpaqueService:
    def __init__(self) -> None:
        self._sidecar = None

    @property
    def enabled(self) -> bool:
        return bool(
            getattr(settings, "OPAQUE_SIDECAR_URL", "")
            and getattr(settings, "OPAQUE_SIDECAR_TOKEN", "")
        )

    @property
    def sidecar(self):
        if not self.enabled:
            raise OpaqueUnavailableError("OPAQUE is not configured on this server")
        if self._sidecar is None:
            try:
                self._sidecar = make_sidecar()
            except SidecarError as exc:
                raise OpaqueUnavailableError(str(exc)) from exc
        return self._sidecar

    def encode_base64(self, raw: bytes) -> str:
        return self.sidecar.encode_base64(raw)

    def decode_base64(self, value: str) -> bytes:
        return self.sidecar.decode_base64(value)

    async def healthy(self) -> bool:
        if not self.enabled:
            return False
        try:
            return await sync_to_async(self.sidecar.check_health)()
        except Exception:
            return False

    # -- registration ---------------------------------------------------

    async def register_user_start_async(self, *, cred_id: str, reg_request: str) -> str:
        # The sidecar speaks base64 on the wire, exactly like the client. Decoding
        # here would double-decode, so strings pass through untouched.
        try:
            result = await sync_to_async(self.sidecar.register_start)(reg_request, cred_id)
        except SidecarError as exc:
            logger.error("OPAQUE register start failed: %s", exc)
            raise OpaqueUnavailableError(str(exc)) from exc
        return result["reg_response"]

    async def register_user_finish_async(self, *, user, cred_id: str, reg_record: str) -> str:
        return await sync_to_async(self._store_record)(user.id, cred_id, reg_record)

    async def reenroll_after_recovery(self, *, user, cred_id: str, reg_record: bytes) -> str:
        return await sync_to_async(self._store_record)(user.id, cred_id, reg_record)

    def _store_record(self, user_id, cred_id: str, reg_record: str) -> str:
        try:
            result = self.sidecar.register_finish(reg_record, cred_id)
        except SidecarError as exc:
            logger.error("OPAQUE register finish failed: %s", exc)
            raise OpaqueUnavailableError(str(exc)) from exc

        stored = result["record"]
        from .models import User

        with transaction.atomic():
            db_user = User.objects.select_for_update().get(id=user_id)
            # The password hash is deliberately kept. A CLI that predates
            # OPAQUE cannot perform this exchange, and those installs cannot be
            # updated, so removing the password would make the account
            # unreachable from every already-deployed client. OPAQUE becomes
            # the preferred method, not the only one.
            db_user.opaque_record = stored
            db_user.opaque_registered_at = timezone.now()
            db_user.save(update_fields=["opaque_record", "opaque_registered_at"])
        return stored

    # -- login ----------------------------------------------------------

    async def login_start_async(
        self, *, cred_id: str, ke1: str, email: str
    ) -> tuple[str, str]:
        user = await sync_to_async(self._enrolled_user)(email)
        await self._guard_challenge(user.id)
        try:
            # The record is server state. Reading it here is what lets a second
            # device log in with nothing but the password.
            result = await sync_to_async(self.sidecar.login_start)(
                ke1, user.opaque_record, cred_id
            )
        except SidecarError as exc:
            logger.error("OPAQUE login start failed: %s", exc)
            raise OpaqueUnavailableError(str(exc)) from exc
        return result["ke2"], result["server_state"]

    async def login_finish_async(
        self, *, request, cred_id: str, ke3: str, server_state: str, email: str
    ):
        try:
            result = await sync_to_async(self.sidecar.login_finish)(ke3, server_state, cred_id)
        except SidecarError as exc:
            logger.error("OPAQUE login finish failed: %s", exc)
            raise OpaqueUnavailableError(str(exc)) from exc
        session_key = result.get("session_key") if isinstance(result, dict) else None
        if isinstance(session_key, dict):
            session_key = session_key.get("session_key")
        if not session_key:
            logger.error("OPAQUE sidecar returned no session key: %r", result)
            raise OpaqueUnavailableError("OPAQUE sidecar returned no session key")

        from apps.common.exceptions import AuthenticationError

        user = await sync_to_async(self._enrolled_user)(email, consume=True)
        if not user:
            raise AuthenticationError("Invalid Credentials")

        from .selectors import AccountSelector
        from .services import AccountService

        tokens = await sync_to_async(user.tokens)()
        expires_at = timezone.now() + settings.SIMPLE_JWT.get(
            "ACCESS_TOKEN_LIFETIME", timedelta(hours=6)
        )
        workspaces = await AccountSelector.get_user_workspaces_data(user=user)
        await AccountService.stamp_user_activity(user=user)

        return {
            **tokens,
            "expires_at": expires_at.isoformat(),
            "key_salt": user.key_salt,
            "encrypted_private_key": user.encrypted_private_key,
            "vault": user.vault,
            "vault_version": user.vault_version,
            "session_key": session_key,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "public_key": user.public_key,
                "billing_id": user.billing_id,
            },
            "workspaces": workspaces,
        }

    def _enrolled_user(self, email: str, consume: bool = False):
        from apps.common.exceptions import AuthenticationError

        from .models import OpaqueLoginChallenge, User

        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if user is None or not user.opaque_record or not user.opaque_registered_at:
            # Uniform failure: never reveal whether the account or enrollment exists.
            raise AuthenticationError("Invalid Credentials")

        if consume:
            challenge = (
                OpaqueLoginChallenge.objects.filter(user=user, used_at__isnull=True)
                .order_by("-created_at")
                .first()
            )
            if challenge is None or challenge.is_expired():
                raise AuthenticationError("OPAQUE login challenge expired")
            challenge.consume()
        return user

    # -- challenge ------------------------------------------------------

    async def _guard_challenge(self, user_id) -> str:
        return await sync_to_async(self._issue_challenge)(user_id)

    def _issue_challenge(self, user_id) -> str:
        from apps.common.exceptions import RateLimitError

        from .models import OpaqueLoginChallenge, User

        now = timezone.now()
        with transaction.atomic():
            user = User.objects.select_for_update().get(id=user_id)
            OpaqueLoginChallenge.objects.filter(user=user, expires_at__lt=now).delete()
            recent = OpaqueLoginChallenge.objects.filter(
                user=user, created_at__gte=now - CHALLENGE_WINDOW
            ).count()
            if recent >= MAX_CHALLENGES_PER_WINDOW:
                raise RateLimitError("Too many OPAQUE login attempts. Try again in 15 minutes.")
            challenge = OpaqueLoginChallenge.objects.create(
                user=user,
                challenge_id=secrets.token_urlsafe(32),
                server_state=b"",
                expires_at=now + CHALLENGE_TTL,
            )
        return challenge.challenge_id
