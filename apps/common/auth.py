# Standard library
import hmac
import logging

# Django
from django.conf import settings

# Third-party
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


logger = logging.getLogger("apps.common.auth")


class JWTAuth(HttpBearer):
    """
    Django Ninja auth class wrapping SimpleJWT token validation.
    
    Extracts the Bearer token from the Authorization header,
    validates it via SimpleJWT, and sets request.user.
    """

    def authenticate(self, request, token):
        jwt_auth = JWTAuthentication()
        try:
            validated_token = jwt_auth.get_validated_token(token)
            user = jwt_auth.get_user(validated_token)
            request.user = user
            return user
        except (InvalidToken, TokenError):
            return None


class ResolverServiceKeyAuth(HttpBearer):
    """
    Auth class for resolver-facing internal endpoints.
    
    Validates the Bearer token against the RESOLVER_SERVICE_KEY
    environment variable using constant-time comparison.
    
    Resolver endpoints must NEVER be accessible via user session auth.
    """

    def authenticate(self, request, token):
        expected = getattr(settings, "RESOLVER_SERVICE_KEY", None)
        if not expected:
            logger.warning("RESOLVER_SERVICE_KEY not configured — rejecting all internal requests")
            return None
        # Constant-time comparison to prevent timing attacks
        if hmac.compare_digest(token, expected):
            return token
        return None
