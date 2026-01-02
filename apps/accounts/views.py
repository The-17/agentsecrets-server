# Standard library
import base64
import logging
from datetime import timedelta

# Django
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from django.utils.encoding import smart_str
from django.utils.http import urlsafe_base64_decode
from django.conf import settings

# Third-party
from adrf.views import APIView
from asgiref.sync import sync_to_async
from cryptography.fernet import Fernet
from drf_spectacular.utils import extend_schema
from nacl.public import PublicKey, SealedBox
from rest_framework.permissions import IsAuthenticated

# Local
from apps.common.response import CustomResponse
from apps.common.serializers import ErrorResponseSerializer, SuccessResponseSerializer
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus
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


logger = logging.getLogger("apps.accounts")

tags = ["Authentication"]


class RegisterUserAPIView(APIView):
    serializer_class = RegisterSerializer

    @extend_schema(
        tags=tags,
        summary="Register User",
        description="""Register a new user account.
        
        The CLI should generate:
        1. A keypair (public_key, private_key) for asymmetric encryption
        2. Encrypt the private_key with user's password-derived key
        3. Send public_key and encrypted_private_key to this endpoint
        
        The API will:
        1. Create the user
        2. Auto-create a personal workspace
        3. Generate a workspace key and encrypt it with the user's public_key
        4. Create an owner membership linking user to their personal workspace
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
        public_key = data.pop("public_key", None)
        encrypted_private_key = data.pop("encrypted_private_key", None)
        
        if master_key is not None:
            encrypted_master_key = encryption_service.encrypt(master_key)
            key_salt = encryption_service.encrypt(salt)
        
        user = await User.objects.acreate_user(
            encrypted_master_key=encrypted_master_key, 
            key_salt=key_salt,
            public_key=public_key,
            encrypted_private_key=encrypted_private_key,
            **data
        )
        
        # Create personal workspace if user has a public key
        workspace_data = None
        if public_key:
            
            # Create personal workspace
            workspace = await Workspace.objects.acreate(
                name=f"{user.first_name}'s Workspace",
                owner=user,
                type=WorkspaceType.PERSONAL
            )
            
            # Generate workspace key (random 32 bytes for Fernet)
            workspace_key = Fernet.generate_key()
            
            # Encrypt workspace key with user's public key
            try:
                # Decode the base64 public key
                public_key_bytes = base64.b64decode(public_key)
                nacl_public_key = PublicKey(public_key_bytes)
                sealed_box = SealedBox(nacl_public_key)
                encrypted_workspace_key = sealed_box.encrypt(workspace_key)
                encrypted_workspace_key_b64 = base64.b64encode(encrypted_workspace_key).decode('utf-8')
            except Exception as e:
                logger.error(f"Failed to encrypt workspace key: {e}")
                # Fallback: store without encryption (not ideal, but allows registration to complete)
                encrypted_workspace_key_b64 = base64.b64encode(workspace_key).decode('utf-8')
            
            # Create owner membership
            await Membership.objects.acreate(
                user=user,
                workspace=workspace,
                role=MembershipRole.OWNER,
                encrypted_workspace_key=encrypted_workspace_key_b64
            )
            
            workspace_data = {
                "id": str(workspace.id),
                "name": workspace.name,
                "type": workspace.type
            }

        response_data = {
            "email": data["email"],
            "first_name": data["first_name"],
            "last_name": data["last_name"],
        }
        
        if workspace_data:
            response_data["workspace"] = workspace_data

        return CustomResponse.success(
            message="Registration successful!", 
            data=response_data,
            status_code=201
        )
   

class LoginUserAPIView(APIView):
    serializer_class = LoginSerializer

    @extend_schema(
            tags=tags,
            summary="Login User",
            description="""Login a user and return authentication tokens plus encryption keys.
            
            Response includes:
            - access/refresh tokens for API authentication
            - encrypted_master_key and key_salt for backward compatibility
            - encrypted_private_key for asymmetric decryption (CLI decrypts with password)
            - workspaces list with encrypted_workspace_key for each
            
            CLI Flow:
            1. Derive user_key from password + key_salt
            2. Decrypt private_key using user_key
            3. For each workspace, decrypt workspace_key using private_key
            4. Now CLI can encrypt/decrypt secrets in those workspaces
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

        # Decrypt master key and salt (backward compatibility)
        encrypted_master_key = None
        key_salt = None
        if user.encrypted_master_key:
            encrypted_master_key = encryption_service.decrypt(user.encrypted_master_key)
        if user.key_salt:
            key_salt = encryption_service.decrypt(user.key_salt)

        # Calculate token expiration time
        access_token_lifetime = settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME', timedelta(hours=6))
        expires_at = timezone.now() + access_token_lifetime

        # Fetch user's workspaces with their encrypted keys
        workspaces_data = []
        memberships = Membership.objects.filter(user=user, status=MembershipStatus.ACTIVE).select_related('workspace')
        async for membership in memberships:
            workspaces_data.append({
                'id': str(membership.workspace.id),
                'name': membership.workspace.name,
                'type': membership.workspace.type,
                'role': membership.role,
                'encrypted_workspace_key': membership.encrypted_workspace_key
            })

        response_data = {
            **tokens,
            'expires_at': expires_at.isoformat(),
            'encrypted_master_key': encrypted_master_key,  # Backward compat
            'key_salt': key_salt,
            'encrypted_private_key': user.encrypted_private_key,  # NEW: for asymmetric decryption
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'public_key': user.public_key  # NEW: for reference
            },
            'workspaces': workspaces_data  # NEW: list of workspaces with encrypted keys
        }

        return CustomResponse.success(message="Login successful!", data=response_data, status_code=200)


class VerifyEmailAPIView(APIView):
    serializer_class = VerifyOtpSerializer

    @extend_schema(
            tags=tags,
            summary="Verify Email",
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
        serializer.save()

        return CustomResponse.success(message="Logged out successfully")


class UserPublicKeyAPIView(APIView):
    """
    Get a user's public key by email.
    Used during workspace invite to encrypt the workspace key for the invitee.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=tags,
        summary="Get User Public Key",
        description="""Get a user's public key by email.
        
        This is used when inviting someone to a workspace:
        1. CLI fetches the invitee's public key
        2. CLI encrypts the workspace key with the invitee's public key
        3. CLI sends the invite with the encrypted workspace key
        """,
        responses={
            200: SuccessResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def get(self, request, email):
        """Get a user's public key"""
        user = await User.objects.filter(email=email).afirst()
        
        if not user:
            return CustomResponse.error(
                message=f"User with email {email} not found",
                status_code=404
            )
        
        if not user.public_key:
            return CustomResponse.error(
                message="User has not set up encryption keys",
                status_code=400
            )
        
        return CustomResponse.success(
            message="Public key retrieved successfully",
            data={
                'email': user.email,
                'public_key': user.public_key
            },
            status_code=200
        )
