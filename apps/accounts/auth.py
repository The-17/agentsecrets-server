# Standard library
import hmac
import logging

# Django
from django.conf import settings

# Third-party
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


logger = logging.getLogger("apps.accounts.auth")


class JWTAuth(HttpBearer):
    """
    Django Ninja auth class wrapping SimpleJWT token validation.
    
    Extracts the Bearer token from the Authorization header,
    validates it via SimpleJWT, and sets request.user.
    """

    def __call__(self, request):
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            return request.user
        return super().__call__(request)

    def authenticate(self, request, token):
        jwt_auth = JWTAuthentication()
        try:
            validated_token = jwt_auth.get_validated_token(token)
            user = jwt_auth.get_user(validated_token)
            request.user = user
            return user
        except (InvalidToken, TokenError):
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

    def __call__(self, request):
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            return request.user
        return super().__call__(request)

    def authenticate(self, request, token):
        # Try Resolver Service Key first
        res = ResolverServiceKeyAuth().authenticate(request, token)
        if res is not None:
            return res

        # Fall back to User JWT
        return JWTAuth().authenticate(request, token)
