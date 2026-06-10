# Standard library
import base64
import logging
from datetime import timedelta

# Django
from django.conf import settings
from django.contrib.auth import authenticate, aauthenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from asgiref.sync import sync_to_async

# Third-party
from cryptography.fernet import Fernet
from nacl.public import PublicKey, SealedBox
from ninja_extra import api_controller, route
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

# Local
from apps.common.auth import JWTAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse
from apps.common.exceptions import (
    AuthenticationError, NotFoundError, BodyValidationError, ConflictError, ErrorCode,
)
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus
from .models import User, OneTimePassword
from .schemas import (
    RegisterSchema, LoginSchema, LogoutSchema, VerifyOtpSchema,
    ResendOtpSchema, ResetPasswordSchema, SetNewPasswordSchema,
    ChangePasswordSchema, RefreshTokenSchema,
)

logger = logging.getLogger("apps.accounts")


@api_controller("/auth", tags=["Auth"], auth=None)
class AuthController:

    @route.post("/register/", response={201: dict, 422: ErrorResponse})
    async def register(self, request, data: RegisterSchema):
        existing = await User.objects.aget_or_none(email=data.email)
        if existing:
            raise ConflictError("Email already registered")

        payload = data.dict()
        salt = payload.pop("key_salt")
        public_key = payload.pop("public_key", None)
        encrypted_private_key = payload.pop("encrypted_private_key", None)
        payload.pop("terms_agreement")

        key_salt = encryption_service.encrypt(salt) if salt else None
        user = await User.objects.acreate_user(
            key_salt=key_salt, public_key=public_key,
            encrypted_private_key=encrypted_private_key, **payload,
        )

        workspace_data = None
        if public_key:
            workspace = await Workspace.objects.acreate(
                name=f"{user.first_name}'s Workspace", owner=user, type=WorkspaceType.PERSONAL,
            )
            workspace_key = Fernet.generate_key()
            try:
                pk_bytes = base64.b64decode(public_key)
                sealed = SealedBox(PublicKey(pk_bytes))
                ewk = base64.b64encode(sealed.encrypt(workspace_key)).decode("utf-8")
            except Exception as e:
                logger.error(f"Failed to encrypt workspace key: {e}")
                ewk = base64.b64encode(workspace_key).decode("utf-8")

            await Membership.objects.acreate(
                user=user, workspace=workspace, role=MembershipRole.OWNER,
                encrypted_workspace_key=ewk,
            )
            workspace_data = {"id": str(workspace.id), "name": workspace.name, "type": workspace.type}

        resp = {"email": data.email, "first_name": data.first_name, "last_name": data.last_name}
        if workspace_data:
            resp["workspace"] = workspace_data

        return CustomResponse.success(message="Registration successful!", data=resp, status_code=201)

    @route.post("/login/", response={200: dict, 401: ErrorResponse})
    async def login(self, request, data: LoginSchema):
        user = await aauthenticate(request, email=data.email, password=data.password)
        if not user:
            raise AuthenticationError("Invalid Credentials")

        tokens = await sync_to_async(user.tokens)()
        key_salt = encryption_service.decrypt(user.key_salt) if user.key_salt else None
        expires_at = timezone.now() + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))

        # Stamp user activity on successful login
        from apps.accounts.utils import stamp_user_activity_async
        await stamp_user_activity_async(user)

        workspaces_data = []
        async for m in Membership.objects.filter(user=user, status=MembershipStatus.ACTIVE).select_related("workspace"):
            workspaces_data.append({
                "id": str(m.workspace.id), "name": m.workspace.name, "type": m.workspace.type,
                "role": m.role, "encrypted_workspace_key": m.encrypted_workspace_key,
            })

        return CustomResponse.success(message="Login successful!", data={
            **tokens, "expires_at": expires_at.isoformat(), "key_salt": key_salt,
            "encrypted_private_key": user.encrypted_private_key,
            "user": {"id": str(user.id), "email": user.email, "first_name": user.first_name, "last_name": user.last_name, "public_key": user.public_key},
            "workspaces": workspaces_data,
        })

    @route.post("/verify-email/", response={200: SuccessResponse, 400: ErrorResponse})
    async def verify_email(self, request, data: VerifyOtpSchema):
        user = await User.objects.aget_or_none(email=data.email)
        if not user:
            raise AuthenticationError("Verification Failed")
        if user.is_email_verified:
            raise BodyValidationError("email", "Email already verified")
        try:
            otp = await OneTimePassword.objects.aget(code=data.otp)
        except OneTimePassword.DoesNotExist:
            raise AuthenticationError("Verification Failed")
        if otp.user_id != user.id:
            raise AuthenticationError("Verification Failed")
        user.is_email_verified = True
        await user.asave(update_fields=["is_email_verified"])
        return CustomResponse.success(message="Email verified successfully!")

    @route.post("/resend-otp/", response={200: SuccessResponse, 400: ErrorResponse})
    async def resend_otp(self, request, data: ResendOtpSchema):
        user = await User.objects.aget_or_none(email=data.email)
        if not user:
            raise NotFoundError("User does not exist")
        if user.is_email_verified:
            raise BodyValidationError("email", "Email already verified")
        return CustomResponse.success(message="OTP sent successfully!")

    @route.post("/reset-password-request/", response={200: SuccessResponse})
    async def reset_password_request(self, request, data: ResetPasswordSchema):
        return CustomResponse.success(message="An email with a link to reset your password has been sent to you")

    @route.post("/reset-password-confirm/", response={200: SuccessResponse, 400: ErrorResponse})
    async def reset_password_confirm(self, request, data: SetNewPasswordSchema):
        user_id = smart_str(urlsafe_base64_decode(data.uidb64))
        user = await User.objects.aget_or_none(id=user_id)
        if not user:
            raise NotFoundError("User not found")
        if not PasswordResetTokenGenerator().check_token(user, data.token):
            raise AuthenticationError("Token is invalid or expired")
        return CustomResponse.success(message="Credentials validated successfully")

    @route.patch("/set-new-password/", response={200: SuccessResponse, 400: ErrorResponse})
    async def set_new_password(self, request, data: SetNewPasswordSchema):
        user_id = smart_str(urlsafe_base64_decode(data.uidb64))
        user = await User.objects.aget_or_none(id=user_id)
        if not user:
            raise NotFoundError("User not found")
        if not PasswordResetTokenGenerator().check_token(user, data.token):
            raise AuthenticationError("Token is invalid or expired")
        user.set_password(data.password)
        if data.key_salt:
            user.key_salt = encryption_service.encrypt(data.key_salt)
        if data.encrypted_private_key:
            user.encrypted_private_key = data.encrypted_private_key
        await user.asave()
        return CustomResponse.success(message="Password reset successfully")

    @route.patch("/change-password/", response={200: SuccessResponse, 400: ErrorResponse}, auth=JWTAuth())
    async def change_password(self, request, data: ChangePasswordSchema):
        user = request.auth
        if not user.check_password(data.current_password):
            raise BodyValidationError("current_password", "Current password is incorrect")
        user.set_password(data.new_password)
        user.key_salt = encryption_service.encrypt(data.key_salt)
        user.encrypted_private_key = data.encrypted_private_key
        await user.asave()
        return CustomResponse.success(message="Password changed successfully")

    @route.post("/logout/", response={200: SuccessResponse, 400: ErrorResponse}, auth=JWTAuth())
    async def logout(self, request, data: LogoutSchema = None):
        if data and data.refresh_token:
            try:
                await sync_to_async(RefreshToken(data.refresh_token).blacklist)()
            except TokenError:
                pass  # Ignore invalid token on logout
        return CustomResponse.success(message="Logged out successfully")

    @route.post("/refresh/", response={200: dict, 401: ErrorResponse})
    async def refresh(self, request, data: RefreshTokenSchema):
        try:
            refresh = await sync_to_async(RefreshToken)(data.refresh)
            expires_at = timezone.now() + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))

            # Generate the new access token BEFORE rotation so the payload is correct
            new_access = str(refresh.access_token)

            # Perform token rotation to match SIMPLE_JWT settings:
            # 1. Blacklist the old refresh token
            # 2. Issue a new refresh token with fresh jti/exp/iat
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

            # Extract user_id and stamp user activity on successful refresh
            user_id = refresh.payload.get("user_id")
            if user_id:
                try:
                    user = await User.objects.aget(id=user_id)
                    from apps.accounts.utils import stamp_user_activity_async
                    await stamp_user_activity_async(user)
                except Exception as e:
                    logger.error(f"Refresh: Failed to stamp user activity: {e}")

            response_data = {
                "access": new_access,
                "expires_at": expires_at.isoformat(),
            }
            if rotate:
                response_data["refresh"] = str(refresh)

            return CustomResponse.success(message="Token refreshed successfully", data=response_data)
        except TokenError:
            raise AuthenticationError("Invalid or expired refresh token")


@api_controller("/users", tags=["Users"], auth=None)
class UserController:

    @route.get("/{email}/public-key/", response={200: dict, 404: ErrorResponse})
    async def get_public_key(self, request, email: str):
        user = await User.objects.aget_or_none(email=email)
        if not user:
            raise NotFoundError(f"User with email {email} not found")
        if not user.public_key:
            raise BodyValidationError("public_key", "User has not set up encryption keys")
        return CustomResponse.success(
            message="Public key retrieved successfully",
            data={"email": user.email, "public_key": user.public_key},
        )
