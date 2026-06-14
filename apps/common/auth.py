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
            logger.info(f"JWTAuth: Successfully authenticated user {user.email}")
            return user
        except (InvalidToken, TokenError) as e:
            logger.warning(f"JWTAuth: Token validation failed — {type(e).__name__}: {e}")
            return None
        except Exception as e:
            logger.error(f"JWTAuth: Unexpected error during authentication — {type(e).__name__}: {e}")
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


class InternalOrUserAuth(HttpBearer):
    """
    Combined auth class that allows BOTH ResolverServiceKeyAuth and JWTAuth.
    Manually checks both to avoid framework bugs with lists of authenticators.
    """

    def __call__(self, request):
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            return request.user
        return super().__call__(request)

    def authenticate(self, request, token):
        logger.info(f"InternalOrUserAuth: Received token (first 20 chars): {token[:20]}...")

        # Try Resolver Service Key first
        res = ResolverServiceKeyAuth().authenticate(request, token)
        if res is not None:
            logger.info("InternalOrUserAuth: Authenticated via ResolverServiceKey")
            return res

        # Try User JWT
        res = JWTAuth().authenticate(request, token)
        if res is not None:
            logger.info(f"InternalOrUserAuth: Authenticated via JWT as {res}")
            return res

        logger.warning("InternalOrUserAuth: Both ResolverServiceKey and JWT failed")
        return None
