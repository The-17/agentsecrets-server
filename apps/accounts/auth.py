# Standard library
import base64
import hashlib
import logging
import time

# Django
from django.conf import settings
from django.utils.translation import gettext_lazy as _

# Third-party
from ninja.security import HttpBearer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError, AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings

try:
    from nacl.exceptions import BadSignature
except ImportError:  # PyNaCl < 1.5 names it BadSignatureError
    from nacl.exceptions import BadSignatureError as BadSignature
from nacl.signing import VerifyKey

from apps.accounts.models import User


logger = logging.getLogger("apps.accounts.auth")


class StatelessJWTAuthentication(JWTAuthentication):
    """
    Validates token signature/expiration in memory and builds the User
    instance directly from verified claims when present, avoiding a database
    query on every authenticated request.
    """

    def get_user(self, validated_token):
        try:
            user_id = validated_token[api_settings.USER_ID_CLAIM]
        except KeyError:
            raise InvalidToken(_("Token contained no recognizable user identification"))

        email = validated_token.get("email")
        if email:
            user = User(
                id=user_id,
                email=email,
                first_name=validated_token.get("first_name", ""),
                last_name=validated_token.get("last_name", ""),
                billing_id=validated_token.get("billing_id"),
                is_active=True,
                is_staff=validated_token.get("is_staff", False),
                is_superuser=validated_token.get("is_superuser", False),
            )
            user._state.adding = False
            user._state.db = "default"
            return user

        # Fallback for legacy tokens without embedded profile claims
        try:
            user = self.user_model.objects.only(
                "id", "email", "first_name", "last_name", "billing_id", "is_active", "is_staff", "is_superuser"
            ).get(**{api_settings.USER_ID_FIELD: user_id})
        except self.user_model.DoesNotExist:
            raise AuthenticationFailed(_("User not found"), code="user_not_found")

        if not user.is_active:
            raise AuthenticationFailed(_("User is inactive"), code="user_inactive")

        return user


class JWTAuth(HttpBearer):
    """
    Django Ninja bearer auth handler using stateless JWT validation.
    Sets request.user to the authenticated user on success.
    """

    def __init__(self):
        super().__init__()
        self._jwt_auth = StatelessJWTAuthentication()

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


class InternalOrUserAuth(HttpBearer):
    """
    Combined auth class for internal endpoints: User JWT only.

    The shared-secret ResolverServiceKeyAuth path was retired (ADR 008):
    resolver-originated state-changing RPCs authenticate with
    ResolverSignatureAuth (Ed25519, no shared secret) instead.
    """

    def __init__(self):
        super().__init__()
        self._jwt_auth = JWTAuth()

    def __call__(self, request):
        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            return request.user
        return super().__call__(request)

    def authenticate(self, request, token):
        return self._jwt_auth.authenticate(request, token)


class ResolverSignatureAuth(HttpBearer):
    """
    Authenticates resolver-originated state-changing internal RPCs
    (rotation execute / family-revoke) with an Ed25519 request signature.

    The resolver holds the private half (`RESOLVER_SIGNING_KEY`); the control
    plane verifies against `RESOLVER_SIGNING_PUBKEY`. No shared secret exists,
    nothing a self-hoster copies from this repo can forge, and verification
    works through edge-terminated TLS (ADR 008).

    Canonical payload: ``{timestamp}\\n{METHOD}\\n{path}\\n{sha256_hex(body)}``.
    """

    freshness_window_s = 300

    def __call__(self, request):
        # No Authorization header is involved: identity is proven by the
        # Ed25519 signature headers alone. Bypass HttpBearer's Bearer parsing.
        return self.authenticate(request, None)

    def authenticate(self, request, token):
        del token
        try:
            return self._verify(request)
        except Exception as exc:
            logger.warning("ResolverSignatureAuth rejected request: %s", type(exc).__name__)
            return None

    def _verify(self, request):
        pubkey_hex = getattr(settings, "RESOLVER_SIGNING_PUBKEY", "") or ""
        if not pubkey_hex:
            return None
        meta = request.META
        key_id = meta.get("HTTP_X_RESOLVER_KEY_ID", "")
        timestamp = meta.get("HTTP_X_RESOLVER_TIMESTAMP", "")
        signature_b64 = meta.get("HTTP_X_RESOLVER_SIGNATURE", "")
        if not (key_id and timestamp and signature_b64):
            return None
        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            return None
        if abs(time.time() - ts) > self.freshness_window_s:
            return None
        body = request.body or b""
        body_hash = hashlib.sha256(body).hexdigest()
        path = meta.get("PATH_INFO", "") or request.path
        payload = "\n".join([timestamp, request.method.upper(), path, body_hash])
        try:
            verify_key = VerifyKey(bytes.fromhex(pubkey_hex))
            signature = base64.b64decode(signature_b64)
            verify_key.verify(signature + payload.encode())
        except (ValueError, BadSignature):
            return None
        return key_id
