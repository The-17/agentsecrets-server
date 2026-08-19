import logging
from typing import Any
from ninja_extra import api_controller, route

from apps.common.auth import JWTAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse, DataResponse
from .schemas import (
    RegisterSchema,
    LoginSchema,
    LogoutSchema,
    VerifyOtpSchema,
    ResendOtpSchema,
    ResetPasswordSchema,
    SetNewPasswordSchema,
    ChangePasswordSchema,
    RefreshTokenSchema,
    RegisterResponseDataSchema,
    LoginResponseDataSchema,
    TokenRefreshResponseDataSchema,
    UserPublicKeyResponseSchema,
)
from .selectors import AccountSelector
from .services import AccountService

logger = logging.getLogger("apps.accounts")


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
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "public_key": user.public_key,
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

    @route.patch("/change-password/", response={200: SuccessResponse, 400: ErrorResponse}, auth=JWTAuth())
    async def change_password(self, request, data: ChangePasswordSchema):
        await AccountService.change_password(
            user=request.auth,
            current_password=data.current_password,
            new_password=data.new_password,
            key_salt=data.key_salt,
            encrypted_private_key=data.encrypted_private_key,
        )
        return CustomResponse.success(message="Password changed successfully")

    @route.post("/logout/", response={200: SuccessResponse, 400: ErrorResponse}, auth=JWTAuth())
    async def logout(self, request, data: LogoutSchema = None):
        refresh_token = data.refresh_token if data else None
        await AccountService.logout_user(refresh_token=refresh_token)
        return CustomResponse.success(message="Logged out successfully")

    @route.post("/refresh/", response={200: DataResponse[TokenRefreshResponseDataSchema], 401: ErrorResponse})
    async def refresh(self, request, data: RefreshTokenSchema):
        result = await AccountService.refresh_token(refresh_token_str=data.refresh)
        return CustomResponse.success(
            message="Token refreshed successfully",
            data=result,
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
