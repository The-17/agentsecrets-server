# Standard library
import hmac
import logging

# Django
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# Third-party
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings


logger = logging.getLogger("apps.accounts.auth")


class FastJWTAuthentication(JWTAuthentication):
    """
    Optimized JWT authentication that fetches only essential identity columns,
    avoiding slow SELECTs of large base64 keys and cryptographic salts.
    """

    def get_user(self, validated_token):
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError:
            raise InvalidToken(_("Token contained no recognizable user identification"))

        try:
            user = self.user_model.objects.only(
                "id", "email", "first_name", "last_name", "is_active", "is_staff", "is_superuser"
            ).get(**{api_settings.USER_ID_FIELD: user_id})
        except self.user_model.DoesNotExist:
            raise AuthenticationFailed(_("User not found"), code="user_not_found")

        if not user.is_active:
            raise AuthenticationFailed(_("User is inactive"), code="user_inactive")

        return user


class JWTAuth(HttpBearer):
    """
    Django Ninja auth class wrapping optimized JWT token validation.
    
    Extracts the Bearer token from the Authorization header,
    validates it via FastJWTAuthentication, and sets request.user.
    """

    def __init__(self):
        super().__init__()
        self._jwt_auth = FastJWTAuthentication()

    def __call__(self, request):
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            return request.user
        return super().__call__(request)

    def authenticate(self, request, token):
        try:
            validated_token = self._jwt_auth.get_validated_token(token)
            user = self._jwt_auth.get_user(validated_token)
            request.user = user
            return user
        except (InvalidToken, TokenError, AuthenticationFailed):
            return None
        except Exception as e:
            logger.error(f"JWTAuth: Unexpected error during authentication: {type(e).__name__}")
            return None


class ResolverServiceKeyAuth(HttpBearer):
    """
    Auth class for resolver-facing internal endpoints.
    
    Validates the Bearer token against the RESOLVER_SERVICE_KEY
    environment variable using constant-time comparison.
    """

    def authenticate(self, request, token):
        expected = getattr(settings, "RESOLVER_SERVICE_KEY", None)
        if not expected:
            return None
        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(token, expected):
            return token
        return None


class InternalOrUserAuth(HttpBearer):
    """
    Combined auth class that allows BOTH ResolverServiceKeyAuth and JWTAuth.
    Checks Resolver Service Key first, falls back to User JWT.
    """

    def __init__(self):
        super().__init__()
        self._resolver_auth = ResolverServiceKeyAuth()
        self._jwt_auth = JWTAuth()

    def __call__(self, request):
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            return request.user
        return super().__call__(request)

    def authenticate(self, request, token):
        # Try Resolver Service Key first
        res = self._resolver_auth.authenticate(request, token)
        if res is not None:
            return res

        # Fall back to User JWT
        return self._jwt_auth.authenticate(request, token)
