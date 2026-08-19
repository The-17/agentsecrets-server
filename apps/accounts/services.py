from __future__ import annotations

import base64
import logging
from datetime import timedelta
from typing import Any
from django.conf import settings
from django.contrib.auth import aauthenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.db import transaction
from django.utils import timezone
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from asgiref.sync import sync_to_async
from cryptography.fernet import Fernet
from nacl.public import PublicKey, SealedBox
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from apps.common.exceptions import (
    AuthenticationError,
    NotFoundError,
    BodyValidationError,
    ConflictError,
)
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
)
from .models import User, OneTimePassword
from .schemas import RegisterSchema

logger = logging.getLogger("apps.accounts")


class AccountService:
    """
    Domain service layer for User management and Authentication state transitions.
    """

    @staticmethod
    async def stamp_user_activity(*, user: User) -> None:
        """
        Updates the user's last_active_at timestamp.
        Throttled to once every 15 minutes to prevent write amplification.
        """
        now = timezone.now()
        last_active = user.last_active_at
        if last_active and (now - last_active) < timedelta(minutes=15):
            return

        user.last_active_at = now
        await user.asave(update_fields=["last_active_at"])

    @staticmethod
    def stamp_user_activity_sync(*, user: User) -> None:
        """
        Synchronous variant of stamp_user_activity for WSGI middleware.
        """
        now = timezone.now()
        last_active = user.last_active_at
        if last_active and (now - last_active) < timedelta(minutes=15):
            return

        user.last_active_at = now
        user.save(update_fields=["last_active_at"])

    @staticmethod
    async def register_user(*, data: RegisterSchema) -> dict[str, Any]:
        """
        Registers a new user and provisions their initial personal workspace atomically.
        """
        existing = await User.objects.aget_or_none(email=data.email)
        if existing:
            raise ConflictError("Email already registered")

        payload = data.dict()
        salt = payload.pop("key_salt")
        public_key = payload.pop("public_key", None)
        encrypted_private_key = payload.pop("encrypted_private_key", None)
        payload.pop("terms_agreement", None)

        key_salt = encryption_service.encrypt(salt) if salt else None

        @sync_to_async
        def _create_user_and_workspace():
            with transaction.atomic():
                user = User.objects.create_user(
                    key_salt=key_salt,
                    public_key=public_key,
                    encrypted_private_key=encrypted_private_key,
                    **payload,
                )

                workspace_data = None
                if public_key:
                    workspace = Workspace.objects.create(
                        name=f"{user.first_name}'s Workspace",
                        owner=user,
                        type=WorkspaceType.PERSONAL,
                    )
                    workspace_key = Fernet.generate_key()
                    try:
                        pk_bytes = base64.b64decode(public_key)
                        sealed = SealedBox(PublicKey(pk_bytes))
                        ewk = base64.b64encode(sealed.encrypt(workspace_key)).decode("utf-8")
                    except Exception as e:
                        logger.error("Failed to encrypt workspace key: %s", type(e).__name__)
                        ewk = base64.b64encode(workspace_key).decode("utf-8")

                    Membership.objects.create(
                        user=user,
                        workspace=workspace,
                        role=MembershipRole.OWNER,
                        status=MembershipStatus.ACTIVE,
                        encrypted_workspace_key=ewk,
                    )
                    workspace_data = {
                        "id": str(workspace.id),
                        "name": workspace.name,
                        "type": workspace.type,
                    }

                return user, workspace_data

        user, workspace_data = await _create_user_and_workspace()

        resp: dict[str, Any] = {
            "email": data.email,
            "first_name": data.first_name,
            "last_name": data.last_name,
        }
        if workspace_data:
            resp["workspace"] = workspace_data

        return resp

    @staticmethod
    async def authenticate_user(*, request: Any, email: str, password: str) -> tuple[User, dict[str, Any], str, str | None]:
        """
        Authenticates a user, issues JWT tokens, stamps activity, and returns credentials.
        """
        user = await aauthenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationError("Invalid Credentials")

        tokens = await sync_to_async(user.tokens)()
        key_salt = encryption_service.decrypt(user.key_salt) if user.key_salt else None
        expires_at = timezone.now() + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))

        await AccountService.stamp_user_activity(user=user)

        return user, tokens, expires_at.isoformat(), key_salt

    @staticmethod
    async def verify_email(*, email: str, otp: int) -> None:
        user = await User.objects.aget_or_none(email=email)
        if not user:
            raise AuthenticationError("Verification Failed")
        if user.is_email_verified:
            raise BodyValidationError("email", "Email already verified")
        try:
            record = await OneTimePassword.objects.aget(code=otp)
        except OneTimePassword.DoesNotExist:
            raise AuthenticationError("Verification Failed")
        if record.user_id != user.id:
            raise AuthenticationError("Verification Failed")

        user.is_email_verified = True
        await user.asave(update_fields=["is_email_verified"])

    @staticmethod
    async def resend_otp(*, email: str) -> None:
        user = await User.objects.aget_or_none(email=email)
        if not user:
            raise NotFoundError("User does not exist")
        if user.is_email_verified:
            raise BodyValidationError("email", "Email already verified")

    @staticmethod
    async def confirm_password_reset(*, uidb64: str, token: str) -> User:
        user_id = smart_str(urlsafe_base64_decode(uidb64))
        user = await User.objects.aget_or_none(id=user_id)
        if not user:
            raise NotFoundError("User not found")
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise AuthenticationError("Token is invalid or expired")
        return user

    @staticmethod
    async def set_new_password(
        *,
        uidb64: str,
        token: str,
        password: str,
        key_salt: str | None = None,
        encrypted_private_key: str | None = None,
    ) -> None:
        user = await AccountService.confirm_password_reset(uidb64=uidb64, token=token)
        user.set_password(password)
        if key_salt:
            user.key_salt = encryption_service.encrypt(key_salt)
        if encrypted_private_key:
            user.encrypted_private_key = encrypted_private_key
        await user.asave()

    @staticmethod
    async def change_password(
        *,
        user: User,
        current_password: str,
        new_password: str,
        key_salt: str,
        encrypted_private_key: str,
    ) -> None:
        if not user.check_password(current_password):
            raise BodyValidationError("current_password", "Current password is incorrect")
        user.set_password(new_password)
        user.key_salt = encryption_service.encrypt(key_salt)
        user.encrypted_private_key = encrypted_private_key
        await user.asave()

    @staticmethod
    async def logout_user(*, refresh_token: str | None) -> None:
        if refresh_token:
            try:
                await sync_to_async(RefreshToken(refresh_token).blacklist)()
            except TokenError:
                pass

    @staticmethod
    async def refresh_token(*, refresh_token_str: str) -> dict[str, Any]:
        try:
            refresh = await sync_to_async(RefreshToken)(refresh_token_str)
            expires_at = timezone.now() + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))

            new_access = str(refresh.access_token)

            rotate = settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False)
            if rotate:
                blacklist = settings.SIMPLE_JWT.get("BLACKLIST_AFTER_ROTATION", False)
                if blacklist:
                    try:
                        await sync_to_async(refresh.blacklist)()
                    except AttributeError:
                        pass
                refresh.set_jti()
                refresh.set_exp()
                refresh.set_iat()

            user_id = refresh.payload.get("user_id")
            if user_id:
                try:
                    user = await User.objects.aget(id=user_id)
                    await AccountService.stamp_user_activity(user=user)
                except Exception as e:
                    logger.warning("Refresh: Failed to stamp user activity: %s", type(e).__name__)

            response_data: dict[str, Any] = {
                "access": new_access,
                "expires_at": expires_at.isoformat(),
            }
            if rotate:
                response_data["refresh"] = str(refresh)

            return response_data
        except TokenError:
            raise AuthenticationError("Invalid or expired refresh token")
