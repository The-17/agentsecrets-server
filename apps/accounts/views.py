import logging
from typing import Any
from ninja_extra import api_controller, route

from django.conf import settings

from .auth import JWTAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse, DataResponse
from .schemas import (
    OpaqueRegisterStartSchema,
    OpaqueRegisterFinishSchema,
    OpaqueLoginStartSchema,
    OpaqueLoginFinishSchema,
    OpaqueRegisterStartResponseSchema,
    OpaqueRegisterFinishResponseSchema,
    OpaqueLoginStartResponseSchema,
    OpaqueCapabilitySchema,
    RegisterSchema,
    LoginSchema,
    LogoutSchema,
    VerifyOtpSchema,
    ResendOtpSchema,
    ResetPasswordSchema,
    SetNewPasswordSchema,
    ChangePasswordSchema,
    RecoveryChallengeSchema,
    RecoveryVerifySchema,
    RecoverPasswordSchema,
    RefreshTokenSchema,
    RegisterResponseDataSchema,
    LoginResponseDataSchema,
    TokenRefreshResponseDataSchema,
    UserPublicKeyResponseSchema,
    UserSummarySchema,
    VaultUpdateSchema,
    VaultResponseSchema,
    RecoveryChallengeResponseSchema,
)
from apps.common.exceptions import AuthenticationError
from .selectors import AccountSelector
from .services import AccountService
from .opaque_services import OpaqueService

logger = logging.getLogger("apps.accounts")


@api_controller("/auth/opaque", tags=["Auth OPAQUE"], auth=None)
class OpaqueController:
    """
    OPAQUE (RFC 9807) registration and login. Crypto lives in the Go sidecar;
    these endpoints forward blobs and own per-account enforcement.
    """

    @route.post("/register/start/", response={200: DataResponse[OpaqueRegisterStartResponseSchema], 503: ErrorResponse, 422: ErrorResponse})
    async def register_start(self, request, data: OpaqueRegisterStartSchema):
        manager = OpaqueService()
        reg_response = await manager.register_user_start_async(
            cred_id=data.credential_id,
            reg_request=manager.decode_base64(data.reg_request),
        )
        return CustomResponse.success(
            message="Registration response generated",
            data={
                "reg_response": manager.encode_base64(reg_response),
                "credential_id": data.credential_id,
            },
        )

    @route.post("/register/finish/", response={200: DataResponse[OpaqueRegisterFinishResponseSchema], 401: ErrorResponse, 503: ErrorResponse, 422: ErrorResponse}, auth=JWTAuth())
    async def register_finish(self, request, data: OpaqueRegisterFinishSchema):
        manager = OpaqueService()
        record = await manager.register_user_finish_async(
            user=request.auth,
            cred_id=data.credential_id,
            reg_record=manager.decode_base64(data.reg_record),
        )
        return CustomResponse.success(
            message="OPAQUE enrollment complete; password login is now disabled for this account",
            data={"record": record, "credential_id": data.credential_id},
        )

    @route.post("/login/start/", response={200: DataResponse[OpaqueLoginStartResponseSchema], 401: ErrorResponse, 429: ErrorResponse, 503: ErrorResponse, 422: ErrorResponse})
    async def login_start(self, request, data: OpaqueLoginStartSchema):
        manager = OpaqueService()
        ke2, server_state = await manager.login_start_async(
            cred_id=data.credential_id,
            ke1=manager.decode_base64(data.ke1),
            stored_record=manager.decode_base64(data.record),
            email=data.email,
        )
        return CustomResponse.success(
            message="Login challenge issued",
            data={
                "ke2": manager.encode_base64(ke2),
                "server_state": server_state,
                "credential_id": data.credential_id,
            },
        )

    @route.post("/login/finish/", response={200: DataResponse[LoginResponseDataSchema], 401: ErrorResponse, 409: ErrorResponse, 503: ErrorResponse, 422: ErrorResponse})
    async def login_finish(self, request, data: OpaqueLoginFinishSchema):
        manager = OpaqueService()
        result = await manager.login_finish_async(
            request=request,
            cred_id=data.credential_id,
            ke3=manager.decode_base64(data.ke3),
            server_state=data.server_state,
            email=data.email,
        )
        return CustomResponse.success(message="Login successful!", data=result)


@api_controller("/auth", tags=["Auth"], auth=None)
class AuthController:
    """
    Authentication endpoints for user registration, sessions, and recovery.
    """

    @route.post("/register/", response={201: DataResponse[RegisterResponseDataSchema], 422: ErrorResponse})
    async def register(self, request, data: RegisterSchema):
        result = await AccountService.register_user(data=data)
        return CustomResponse.success(
            message="Registration successful!",
            data=result,
            status_code=201,
        )

    @route.post("/login/", response={200: DataResponse[LoginResponseDataSchema], 401: ErrorResponse})
    async def login(self, request, data: LoginSchema):
        user, tokens, expires_at, key_salt = await AccountService.authenticate_user(
            request=request,
            email=data.email,
            password=data.password,
        )
        workspaces = await AccountSelector.get_user_workspaces_data(user=user)
        return CustomResponse.success(
            message="Login successful!",
            data={
                **tokens,
                "expires_at": expires_at,
                "key_salt": key_salt,
                "encrypted_private_key": user.encrypted_private_key,
                "vault": user.vault,
                "vault_version": user.vault_version,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "public_key": user.public_key,
                    "billing_id": user.billing_id,
                },
                "workspaces": workspaces,
            },
        )

    @route.post("/verify-email/", response={200: SuccessResponse, 400: ErrorResponse})
    async def verify_email(self, request, data: VerifyOtpSchema):
        await AccountService.verify_email(email=data.email, otp=data.otp)
        return CustomResponse.success(message="Email verified successfully!")

    @route.post("/resend-otp/", response={200: SuccessResponse, 400: ErrorResponse})
    async def resend_otp(self, request, data: ResendOtpSchema):
        await AccountService.resend_otp(email=data.email)
        return CustomResponse.success(message="OTP sent successfully!")

    @route.post("/reset-password-request/", response={200: SuccessResponse})
    async def reset_password_request(self, request, data: ResetPasswordSchema):
        return CustomResponse.success(
            message="An email with a link to reset your password has been sent to you"
        )

    @route.post("/reset-password-confirm/", response={200: SuccessResponse, 400: ErrorResponse})
    async def reset_password_confirm(self, request, data: SetNewPasswordSchema):
        await AccountService.confirm_password_reset(uidb64=data.uidb64, token=data.token)
        return CustomResponse.success(message="Credentials validated successfully")

    @route.patch("/set-new-password/", response={200: SuccessResponse, 400: ErrorResponse})
    async def set_new_password(self, request, data: SetNewPasswordSchema):
        await AccountService.set_new_password(
            uidb64=data.uidb64,
            token=data.token,
            password=data.password,
            key_salt=data.key_salt,
            encrypted_private_key=data.encrypted_private_key,
        )
        return CustomResponse.success(message="Password reset successfully")

    @route.patch("/change-password/", response={200: SuccessResponse, 400: ErrorResponse, 422: ErrorResponse, 409: ErrorResponse}, auth=JWTAuth())
    async def change_password(self, request, data: ChangePasswordSchema):
        await AccountService.change_password(
            user=request.auth,
            current_password=data.current_password,
            new_password=data.new_password,
            key_salt=data.key_salt,
            encrypted_private_key=data.encrypted_private_key,
            vault=data.vault,
            expected_version=data.expected_version,
        )
        return CustomResponse.success(message="Password changed successfully")

    @route.get("/vault/", response={200: DataResponse[VaultResponseSchema]}, auth=JWTAuth())
    async def get_vault(self, request):
        from .models import User

        user = await User.objects.aget(id=request.auth.id)
        return CustomResponse.success(
            message="Vault retrieved",
            data={"vault": user.vault, "vault_version": user.vault_version},
        )

    @route.put("/vault/", response={200: DataResponse[VaultResponseSchema], 409: ErrorResponse, 422: ErrorResponse}, auth=JWTAuth())
    async def put_vault(self, request, data: VaultUpdateSchema):
        result = await AccountService.update_vault(
            user=request.auth,
            expected_version=data.expected_version,
            vault=data.vault,
        )
        return CustomResponse.success(message="Vault updated", data=result)

    @route.post("/recover/challenge/", response={200: DataResponse[RecoveryChallengeResponseSchema], 429: ErrorResponse})
    async def recover_challenge(self, request, data: RecoveryChallengeSchema):
        result = await AccountService.create_recovery_challenge(email=data.email)
        return CustomResponse.success(message="Recovery challenge issued", data=result)

    @route.post("/recover/verify/", response={200: DataResponse[LoginResponseDataSchema], 401: ErrorResponse})
    async def recover_verify(self, request, data: RecoveryVerifySchema):
        user, tokens, expires_at, key_salt = await AccountService.verify_recovery(
            email=data.email,
            nonce=data.nonce,
            signature=data.signature,
        )
        workspaces = await AccountSelector.get_user_workspaces_data(user=user)
        return CustomResponse.success(
            message="Recovery verified",
            data={
                **tokens,
                "expires_at": expires_at,
                "key_salt": key_salt,
                "encrypted_private_key": user.encrypted_private_key,
                "vault": user.vault,
                "vault_version": user.vault_version,
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "public_key": user.public_key,
                    "billing_id": user.billing_id,
                },
                "workspaces": workspaces,
            },
        )

    @route.patch("/recover/password/", response={200: SuccessResponse, 401: ErrorResponse, 409: ErrorResponse, 422: ErrorResponse}, auth=JWTAuth())
    async def recover_password(self, request, data: RecoverPasswordSchema):
        if not getattr(request, "recovery_session", False):
            raise AuthenticationError("A recovery session is required to reset the password")
        await AccountService.recover_password(
            user=request.auth,
            new_password=data.new_password,
            key_salt=data.key_salt,
            encrypted_private_key=data.encrypted_private_key,
            vault=data.vault,
            expected_version=data.expected_version,
        )
        return CustomResponse.success(message="Password reset successfully")

    @route.post("/logout/", response={200: SuccessResponse, 400: ErrorResponse}, auth=JWTAuth())
    async def logout(self, request, data: LogoutSchema = None):
        refresh_token = data.refresh_token if data else None
        await AccountService.logout_user(refresh_token=refresh_token)
        return CustomResponse.success(message="Logged out successfully")

    @route.get("/me/", response={200: DataResponse[UserSummarySchema]}, auth=JWTAuth())
    async def get_current_user(self, request):
        user = request.auth
        billing_id = getattr(user, "billing_id", None)
        if not billing_id:
            from .models import User, generate_billing_id
            db_user = await User.objects.aget_or_none(id=user.id)
            if db_user:
                if not db_user.billing_id:
                    db_user.billing_id = generate_billing_id()
                    await db_user.asave(update_fields=["billing_id"])
                billing_id = db_user.billing_id

        return CustomResponse.success(
            message="User profile retrieved",
            data={
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "public_key": user.public_key,
                "billing_id": billing_id,
            },
        )

    @route.post("/refresh/", response={200: DataResponse[TokenRefreshResponseDataSchema], 401: ErrorResponse})
    async def refresh(self, request, data: RefreshTokenSchema):
        result = await AccountService.refresh_token(refresh_token_str=data.refresh)
        return CustomResponse.success(
            message="Token refreshed successfully",
            data=result,
        )

    @route.get("/capabilities/", response={200: DataResponse[OpaqueCapabilitySchema]})
    async def capabilities(self, request):
        """Which auth methods this server supports. Public and side-effect free."""
        opaque = await OpaqueService().healthy()
        return CustomResponse.success(
            message="Capabilities retrieved",
            data=OpaqueCapabilitySchema(
                password=True,
                oauth_github=bool(getattr(settings, "OAUTH_GITHUB_ENABLED", False)),
                oauth_google=bool(getattr(settings, "OAUTH_GOOGLE_ENABLED", False)),
                email_link=bool(getattr(settings, "EMAIL_LINK_ENABLED", False)),
                opaque=opaque,
            ),
        )


@api_controller("/users", tags=["Users"], auth=None)
class UserController:
    """
    Public user endpoints for key discovery.
    """

    @route.get("/{email}/public-key/", response={200: DataResponse[UserPublicKeyResponseSchema], 404: ErrorResponse})
    async def get_public_key(self, request, email: str):
        public_key = await AccountSelector.get_public_key(email=email)
        return CustomResponse.success(
            message="Public key retrieved successfully",
            data={"email": email, "public_key": public_key},
        )
