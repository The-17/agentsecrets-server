from __future__ import annotations

import base64
import hashlib
import logging
import datetime as dt
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
    RateLimitError,
)
from apps.common.services.encryption import EncryptionService as encryption_service
from .vault import (
    build_recovery_challenge,
    recovery_view,
    validate_vault,
    validate_vault_update,
    verify_recovery_signature,
)
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
)
from .models import User, OneTimePassword, VaultRecoveryChallenge
from .schemas import RegisterSchema

logger = logging.getLogger("apps.accounts")


class AccountService:
    """
    Domain service layer for User management and Authentication state transitions.
    """

    @staticmethod
    async def stamp_user_activity_by_id(*, user_id: Any) -> None:
        """
        Updates the user's last_active_at timestamp atomically by ID.
        Throttled to once every 15 minutes. Executes a single conditional UPDATE
        without fetching heavy model fields into memory.
        """
        from django.db.models import Q
        now = timezone.now()
        threshold = now - timedelta(minutes=15)
        await User.objects.filter(
            Q(id=user_id) & (Q(last_active_at__isnull=True) | Q(last_active_at__lt=threshold))
        ).aupdate(last_active_at=now)

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

        if not user.billing_id:
            from .models import generate_billing_id
            user.billing_id = generate_billing_id()
            await user.asave(update_fields=["billing_id"])

        tokens = await sync_to_async(user.tokens)()
        key_salt = encryption_service.decrypt(user.key_salt) if user.key_salt else None
        expires_at = timezone.now() + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))

        await AccountService.stamp_user_activity(user=user)

        return user, tokens, expires_at.isoformat(), key_salt

    @staticmethod
    async def create_recovery_challenge(*, email: str) -> dict[str, Any]:
        """Issue a single-use challenge the client signs with the vault key.

        Unknown, inactive, or vaultless accounts get a decoy challenge so the
        endpoint does not confirm whether an email is registered. The decoy is
        never stored, so it can never verify.
        """
        user = await User.objects.aget_or_none(email__iexact=email)
        now = timezone.now()

        recovery_envelopes = []
        if user and user.vault:
            envelopes = user.vault.get("envelopes")
            if isinstance(envelopes, list):
                recovery_envelopes = [
                    envelope
                    for envelope in envelopes
                    if isinstance(envelope, dict) and envelope.get("type") == "recovery"
                ]

        if not user or not user.is_active or not recovery_envelopes:
            nonce, challenge, expires = build_recovery_challenge(
                "00000000-0000-0000-0000-000000000000"
            )
            return {
                "challenge": challenge,
                "nonce": nonce,
                "expires_at": dt.datetime.fromtimestamp(expires, tz=dt.timezone.utc).isoformat(),
                "user_id": "",
                "vault": None,
                "vault_version": 0,
            }

        recent = await VaultRecoveryChallenge.objects.filter(
            user=user, created_at__gte=now - timedelta(minutes=15)
        ).acount()
        if recent >= 5:
            raise RateLimitError("Too many recovery attempts. Try again in 15 minutes.")

        # Keep the table bounded without a cron job.
        await VaultRecoveryChallenge.objects.filter(
            user=user, expires_at__lt=now
        ).adelete()

        nonce, challenge, expires = build_recovery_challenge(str(user.id))
        await VaultRecoveryChallenge.objects.acreate(
            user=user,
            nonce_hash=hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            challenge=challenge,
            expires_at=dt.datetime.fromtimestamp(expires, tz=dt.timezone.utc),
        )

        return {
            "challenge": challenge,
            "nonce": nonce,
            "expires_at": dt.datetime.fromtimestamp(expires, tz=dt.timezone.utc).isoformat(),
            "user_id": str(user.id),
            "vault": recovery_view(user.vault),
            "vault_version": user.vault_version,
        }

    @staticmethod
    async def verify_recovery(
        *, email: str, nonce: str, signature: str
    ) -> tuple[User, dict[str, Any], str, str | None]:
        """Consume a challenge and verify the client's vault-key signature."""
        user = await User.objects.aget_or_none(email__iexact=email)
        if not user or not user.is_active or not user.vault:
            raise AuthenticationError("Recovery failed")

        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()

        def _consume():
            with transaction.atomic():
                try:
                    record = VaultRecoveryChallenge.objects.select_for_update().get(
                        user=user, nonce_hash=nonce_hash
                    )
                except VaultRecoveryChallenge.DoesNotExist:
                    return None
                if record.used_at is not None or record.expires_at <= timezone.now():
                    return None
                record.used_at = timezone.now()
                record.save(update_fields=["used_at"])
                return record

        record = await sync_to_async(_consume, thread_sensitive=True)()
        if record is None:
            raise AuthenticationError("Recovery failed")

        verify_recovery_signature(
            user.vault.get("vault_pubkey"), record.challenge, signature
        )

        if not user.billing_id:
            from .models import generate_billing_id

            user.billing_id = generate_billing_id()
            await user.asave(update_fields=["billing_id"])

        tokens = await sync_to_async(user.tokens)(recovery=True)
        key_salt = encryption_service.decrypt(user.key_salt) if user.key_salt else None
        expires_at = timezone.now() + settings.SIMPLE_JWT.get(
            "ACCESS_TOKEN_LIFETIME", timedelta(hours=6)
        )
        await AccountService.stamp_user_activity(user=user)

        return user, tokens, expires_at.isoformat(), key_salt

    @staticmethod
    async def recover_password(
        *,
        user: User,
        new_password: str,
        key_salt: str,
        encrypted_private_key: str,
        vault: dict,
        expected_version: int,
    ) -> None:
        """Set a new password from a recovery session, without the old one.

        Callers must have proven vault-key possession first; the view enforces
        the recovery-scoped token before it reaches here.
        """
        validate_vault(vault, user_id=str(user.id))

        def _apply() -> None:
            with transaction.atomic():
                db_user = User.objects.select_for_update().get(id=user.id)
                if db_user.vault is None:
                    raise BodyValidationError("vault", "This account has no vault")
                if db_user.vault_version != expected_version:
                    raise ConflictError("Vault version conflict")
                validate_vault_update(
                    db_user.vault,
                    vault,
                    expected_version=expected_version,
                    user_id=str(db_user.id),
                )
                db_user.vault = vault
                db_user.vault_version = expected_version + 1
                db_user.set_password(new_password)
                # Recovery replaces the credential, so an OPAQUE enrollment for
                # the forgotten password must not survive it. Leaving the flag
                # set refuses password login while the stored record still only
                # matches the old password, which locks the account out of both
                # paths. Clearing both restores password login; the client
                # re-enrolls on its next login.
                db_user.opaque_record = None
                db_user.opaque_registered_at = None
                db_user.key_salt = encryption_service.encrypt(key_salt)
                db_user.encrypted_private_key = encrypted_private_key
                db_user.save()

        await sync_to_async(_apply, thread_sensitive=True)()

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
        vault: dict | None = None,
        expected_version: int | None = None,
    ) -> None:
        if vault is not None and expected_version is None:
            raise BodyValidationError("expected_version", "expected_version is required with vault")
        if vault is not None:
            validate_vault(vault, user_id=str(user.id))

        def _apply() -> None:
            with transaction.atomic():
                db_user = User.objects.select_for_update().get(id=user.id)
                if not db_user.check_password(current_password):
                    raise BodyValidationError("current_password", "Current password is incorrect")

                # OPAQUE enrollment check: password change disabled for opaque-enrolled accounts.
                if getattr(db_user, "opaque_registered_at", None):
                    from apps.common.exceptions import PasswordLoginDisabledError
                    raise PasswordLoginDisabledError(
                        "Password change is disabled for this account. Re-enroll via OPAQUE recovery."
                    )

                if vault is not None:
                    if db_user.vault_version != expected_version:
                        raise ConflictError("Vault version conflict")
                    validate_vault_update(
                        db_user.vault,
                        vault,
                        expected_version=expected_version,
                        user_id=str(db_user.id),
                    )
                    db_user.vault = vault
                    db_user.vault_version = expected_version + 1
                db_user.set_password(new_password)
                db_user.key_salt = encryption_service.encrypt(key_salt)
                db_user.encrypted_private_key = encrypted_private_key
                db_user.save()

        await sync_to_async(_apply, thread_sensitive=True)()

    @staticmethod
    async def update_vault(*, user: User, expected_version: int, vault: dict) -> dict[str, Any]:
        validate_vault(vault, user_id=str(user.id))

        def _apply() -> None:
            with transaction.atomic():
                db_user = User.objects.select_for_update().get(id=user.id)
                if db_user.vault_version != expected_version:
                    raise ConflictError("Vault version conflict")
                validate_vault_update(
                    db_user.vault,
                    vault,
                    expected_version=expected_version,
                    user_id=str(db_user.id),
                )
                db_user.vault = vault
                db_user.vault_version = expected_version + 1
                db_user.save(update_fields=["vault", "vault_version"])

        await sync_to_async(_apply, thread_sensitive=True)()
        return {"vault": vault, "vault_version": expected_version + 1}

    @staticmethod
    async def logout_user(*, refresh_token: str | None) -> None:
        if refresh_token:
            try:
                await sync_to_async(RefreshToken(refresh_token).blacklist)()
            except TokenError:
                pass

    @staticmethod
    async def refresh_token(*, refresh_token_str: str) -> dict[str, Any]:
        """
        Refreshes an access token from a refresh token with rotation support.
        Optimized to process JWT cryptographic operations in a single thread pool hop
        and stamp user activity without querying the full User model.
        """
        try:
            @sync_to_async
            def _process_refresh():
                refresh = RefreshToken(refresh_token_str)
                new_access = str(refresh.access_token)
                rotate = settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False)
                rotated_refresh = None
                if rotate:
                    blacklist = settings.SIMPLE_JWT.get("BLACKLIST_AFTER_ROTATION", False)
                    if blacklist:
                        try:
                            refresh.blacklist()
                        except AttributeError:
                            pass
                    refresh.set_jti()
                    refresh.set_exp()
                    refresh.set_iat()
                    rotated_refresh = str(refresh)
                user_id = refresh.payload.get("user_id")
                return new_access, rotated_refresh, user_id

            new_access, rotated_refresh, user_id = await _process_refresh()
            expires_at = timezone.now() + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))

            if user_id:
                try:
                    await AccountService.stamp_user_activity_by_id(user_id=user_id)
                except Exception as e:
                    logger.warning("Refresh: Failed to stamp user activity: %s", type(e).__name__)

            response_data: dict[str, Any] = {
                "access": new_access,
                "expires_at": expires_at.isoformat(),
            }
            if rotated_refresh:
                response_data["refresh"] = rotated_refresh

            return response_data
        except TokenError:
            raise AuthenticationError("Invalid or expired refresh token")
