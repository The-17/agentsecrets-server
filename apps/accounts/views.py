from doctest import master
from adrf.views import APIView
from .models import User, OneTimePassword
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    VerifyOtpSerializer,
    ResendOtpSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    LogoutSerializer,
)
from apps.common.response import CustomResponse
from django.contrib.auth import authenticate
from asgiref.sync import sync_to_async
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema
from apps.common.serializers import (
    ErrorResponseSerializer,
    SuccessResponseSerializer
)
import logging
from apps.common.services.encryption import EncryptionService as encryption_service


logger = logging.getLogger("apps.accounts")

tags = ["Authentication"]


class RegisterUserAPIView(APIView):
    serializer_class = RegisterSerializer

    @extend_schema(
        tags=tags,
        summary="Register User",
        description="""This endpoint is used to register a user.
        """,
        responses={
            201: SuccessResponseSerializer,
            400: ErrorResponseSerializer
        },
        request=RegisterSerializer,
    )
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        existing_user = await User.objects.aget_or_none(email=data["email"])
        if existing_user:
            return CustomResponse.error(message="Email already registered", status_code=422)
        
        master_key = data.pop("encrypted_master_key")
        salt = data.pop("key_salt")
        if master_key is not None:
            encrypted_master_key = encryption_service.encrypt(master_key)
            key_salt = encryption_service.encrypt(salt)
            print(encrypted_master_key, key_salt)
        
        user = await User.objects.acreate_user(encrypted_master_key=encrypted_master_key, key_salt=key_salt, **data)

        return CustomResponse.success(message="Registration successful!", 
                                      data={
                                          "email":data["email"],
                                          "first_name":data["first_name"],
                                          "last_name":data["last_name"],
                                        },
                                        status_code=201)
   

class LoginUserAPIView(APIView):
    serializer_class = LoginSerializer

    @extend_schema(
            tags=tags,
            summary="Login User",
            description="""This endpoint is used to login a user.
                It returns access and refresh tokens. The access token should be passed for every request
                that reqquires authentication.
            """,
            responses={
                200: SuccessResponseSerializer,
                400: ErrorResponseSerializer
            }
    )
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = await sync_to_async(authenticate, thread_sensitive=True)(email=data["email"], password=data["password"])
        if not user:
            logger.warning(f"Invalid credential used for login")
            return CustomResponse.error(message="Invalid Credentials", status_code=400)
        
        tokens = await sync_to_async(user.tokens, thread_sensitive=True)()
        logger.info(f"User {user.id} logged in successfully")

        encrypted_master_key = encryption_service.decrypt(user.encrypted_master_key)
        key_salt = encryption_service.decrypt(user.key_salt)

        response_data = {
            **tokens,
            'encrypted_master_key': encrypted_master_key, 
            'key_salt': key_salt,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }

        return CustomResponse.success(message="Login successful!", data=response_data, status_code=200)


class VerifyEmailAPIView(APIView):
    serializer_class = VerifyOtpSerializer

    @extend_schema(
            tags=tags,
            summary="Login User",
            description="""This endpoint is used to verify a user's email.
               This endpoint validates the provided otp code and sets the user's email verification status to true
            """,
            responses={
                200: SuccessResponseSerializer,
                400: ErrorResponseSerializer
            }
    )
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = await User.objects.aget_or_none(email=data["email"])
        if not user:
            return CustomResponse.error(message="Verification Failed", status_code=400)
        
        if user.is_email_verified:
            logger.warning(f"User {user.id} tried to verfiy an already verified email address")
            return CustomResponse.error(message="Email already verified", status_code=400)
        
        otp = await OneTimePassword.aget_or_none(code=data["otp"])
        if not otp or data["otp"] != otp.code or otp.user != user:
            return CustomResponse.error(message="Verification Failed", status_code=400)

        user.is_email_verified = True
        await user.asave()
        logger.info(f"Email {user.email} verified successfully")
        # send welcome email
        return CustomResponse.success(message="Email verified successfully!", status_code=200)


class ResendOtpAPIView(APIView):
    serializer_class = ResendOtpSerializer
    
    @extend_schema(
            tags=tags,
            summary="Resend OTP",
            description="""This endpoint is used to resend the OTP code to a user's email.
            """,
            responses={
                200: SuccessResponseSerializer,
                400: ErrorResponseSerializer
            }
    )
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = await User.objects.aget_or_none(email=data["email"])
        if not user:
            return CustomResponse.error(message="User does not exist", status_code=400)
        
        if user.is_email_verified:
            logger.warning(f"User {user.id} tried to verfiy an already verified email address")
            return CustomResponse.error(message="Email already verified", status_code=400)

        # send email
        return CustomResponse.success(message="OTP sent successfully!", status_code=200)


class ResetPasswordRequestAPIView(APIView):
    serializer_class = ResetPasswordSerializer

    @extend_schema(
        tags=tags,
        summary="Reset Password",
        description="""This endpoint is the first step in the password reset process.
        This endpoint sends an email to the user with a link to reset their password
        """,
        responses={
            200: SuccessResponseSerializer,
            400: ErrorResponseSerializer
        }
    )
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        # SendMail.resetpassword(request, email) #send password reset enail
        return CustomResponse.success(message="An email with a link to reset your password has been sent to you")


class ResetPasswordConfirmAPIVIew(APIView):

    @extend_schema(
        tags=tags,
        summary="Reset Password",
        description="""This endpoint is the second step in the password reset process.
        This endpoint validates the provided token(basically makes sure the link is valid). 
        On success, users should be redirected to the reset password page.
        """,
        responses={
            200: SuccessResponseSerializer,
            400: ErrorResponseSerializer
        }
    )
    async def post(self,request, uidb64, token):
        user_id = smart_str(urlsafe_base64_decode(uidb64))

        user  = await User.objects.aget_or_none(id=user_id)
        if not user:
            logger.warning(f"Invalid user received from password reset token")
            return CustomResponse.error(message="User not found", status_code=404)

        is_valid_token = await sync_to_async(PasswordResetTokenGenerator().check_token, thread_sensitive=True)(user, token)
        if not is_valid_token:
            return CustomResponse.error(message="Token is invalid or expired", status_code=400)
        
        logger.info(f"user {user.id} password reset token validated")
        return CustomResponse.success(message="Credentials validated successfully")


class SetNewPasswordAPIView(APIView):
    serializer_class = SetNewPasswordSerializer

    @extend_schema(
        tags=tags,
        summary="Reset Password",
        description="""This endpoint is the third and final step in the password reset process.
        This endpoint sets the new password for the user.
        """,
        responses={
            200: SuccessResponseSerializer,
            400: ErrorResponseSerializer
        }
    )
    async def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        user = await User.objects.aget_or_none(email=data["email"])
        if not user:
            return CustomResponse.error(message="User not found", status_code=404)

        is_valid_token = await sync_to_async(PasswordResetTokenGenerator().check_token, thread_sensitive=True)(user, data["token"])
        if not is_valid_token:
            return CustomResponse.error(message="Token is invalid or expired", status_code=400)

        user.set_password(data["password"])
        await user.asave()

        logger.info(f"user {user.id} password reset successfully")

        return CustomResponse.success(message="Password reset successfully")


class LogoutUserAPIView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=tags,
        summary="Logout",
        description="""This endpoint is used to logout a user.
        """,
        responses={
            200: SuccessResponseSerializer,
            400: ErrorResponseSerializer
        }
    )
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return CustomResponse.success(message="Logged out successfully")

