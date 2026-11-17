"""
OAuth 2.1 Authorization Code + PKCE service for headless agent login.

This is the server half of the `auth_login` flow in the AgentSecrets MCP
bridge (`integrations/mcp`, client id `agentsecrets-mcp`): the human
approves in a browser, the bridge's loopback listener receives the code,
and the token endpoint mints the SAME SimpleJWT pair a normal login
produces — so everything downstream (JWTAuth, refresh rotation,
blacklisting) works unchanged.

Security properties (deliberate, review before relaxing):
- Public client, no client secret (correct per RFC 8252 for loopback apps).
  Authentication strength comes from PKCE S256 + exact redirect matching.
- `redirect_uri` allowlist is loopback-only: `http(s)://127.0.0.1[:port]/callback`
  or `http(s)://localhost[:port]/callback`. Anything else is rejected with
  400 and NEVER redirected to (redirecting errors to an attacker URI would
  leak codes via the Referer header).
- Codes are 32 random bytes (base64url); only SHA-256 hashes are stored.
- Codes live 10 minutes, are bound to (client, redirect_uri, challenge),
  and are claimed atomically — replay of a used/expired code fails closed.
- Token responses are top-level JSON (`access_token`, `refresh_token`,
  `expires_at`), NOT the API `{data: ...}` envelope: the bridge's OAuth
  client reads top-level fields.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from apps.common.exceptions import AuthenticationError
from .models import OAuthAuthorizationCode, User

# Public loopback clients this server provisions codes for. The MCP bridge
# uses `agentsecrets-mcp`. Unknown client_ids are rejected at /authorize.
OAUTH_PUBLIC_CLIENTS = frozenset({"agentsecrets-mcp"})

# Authorization codes live 10 minutes (matches the bridge's login window).
OAUTH_CODE_TTL = timedelta(minutes=10)

# Scopes the bridge requests. Recorded on the code and echoed in the token
# response for audit. Tokens carry normal login power: the approver IS the
# account holder, so scope is descriptive, not a permission filter.
OAUTH_KNOWN_SCOPES = frozenset({"read", "write"})


def hash_code(raw_code: str) -> str:
    return hashlib.sha256(raw_code.encode("utf-8")).hexdigest()


def is_loopback_callback(uri: str) -> bool:
    """
    Accept only loopback callback URIs for the public client:
    http(s)://127.0.0.1[:port]/callback or http(s)://localhost[:port]/callback.
    Port is unrestricted (loopback apps bind ephemeral ports); path must be
    exactly /callback so codes cannot be steered to attacker paths.
    """
    try:
        parts = urlparse(uri)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    if host not in ("127.0.0.1", "localhost"):
        return False
    if parts.path != "/callback":
        return False
    if parts.username or parts.fragment:
        return False
    return True


def verify_pkce(*, verifier: str, challenge: str, method: str) -> bool:
    """Verify a PKCE verifier against the stored challenge (S256 only)."""
    if method != "S256":
        return False
    try:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    except (ValueError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(computed, challenge)


def normalize_scope(raw: str | None) -> str:
    parts = [p for p in (raw or "").split() if p in OAUTH_KNOWN_SCOPES]
    return " ".join(parts)


def issue_code(
    *,
    user: User,
    client_id: str,
    redirect_uri: str,
    scope: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
) -> str:
    """Mint a single-use authorization code. Returns the plaintext code ONCE."""
    raw_code = secrets.token_urlsafe(32)
    OAuthAuthorizationCode.objects.create(
        user=user,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        code_hash=hash_code(raw_code),
        expires_at=timezone.now() + OAUTH_CODE_TTL,
    )
    return raw_code


def redeem_code(
    *,
    raw_code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> tuple[User, str]:
    """
    Validate + atomically claim an authorization code.
    Returns (user, scope). Raises AuthenticationError on any failure —
    callers map that to 401 without distinguishing the reason.
    """
    now = timezone.now()
    try:
        record = OAuthAuthorizationCode.objects.select_related("user").get(
            code_hash=hash_code(raw_code)
        )
    except OAuthAuthorizationCode.DoesNotExist:
        raise AuthenticationError("Invalid authorization code")

    if record.used_at is not None:
        raise AuthenticationError("Invalid authorization code")
    if record.expires_at <= now:
        raise AuthenticationError("Invalid authorization code")
    if record.client_id != client_id or record.redirect_uri != redirect_uri:
        raise AuthenticationError("Invalid authorization code")
    if not verify_pkce(
        verifier=code_verifier,
        challenge=record.code_challenge,
        method=record.code_challenge_method,
    ):
        raise AuthenticationError("Invalid authorization code")

    # Atomic single-use claim: exactly one redemption can win the race.
    claimed = OAuthAuthorizationCode.objects.filter(
        pk=record.pk, used_at__isnull=True
    ).update(used_at=now)
    if claimed != 1:
        raise AuthenticationError("Invalid authorization code")

    return record.user, record.scope


def mint_token_bundle(*, user: User) -> dict[str, Any]:
    """
    Mint the standard SimpleJWT pair for a user (identical shape to login).
    Refresh rotation settings apply as configured; callers keep the old
    refresh token when the server omits a rotated one.
    """
    if not user.is_active:
        raise AuthenticationError("User account is disabled")
    tokens = user.tokens()
    expires_at = timezone.now() + settings.SIMPLE_JWT.get(
        "ACCESS_TOKEN_LIFETIME", timedelta(hours=6)
    )
    return {
        "access_token": tokens["access"],
        "refresh_token": tokens["refresh"],
        "expires_at": expires_at.isoformat(),
    }


def rotate_refresh(*, refresh_token_str: str) -> dict[str, Any]:
    """
    Exchange a refresh token for a new bundle, honoring ROTATE_REFRESH_TOKENS
    / BLACKLIST_AFTER_ROTATION exactly like POST /api/auth/refresh/.
    Raises AuthenticationError when the token is invalid, expired, or revoked.
    """
    try:
        refresh = RefreshToken(refresh_token_str)
        new_access = str(refresh.access_token)
        rotated: str | None = None
        if settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS", False):
            if settings.SIMPLE_JWT.get("BLACKLIST_AFTER_ROTATION", False):
                try:
                    refresh.blacklist()
                except AttributeError:
                    pass
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()
            rotated = str(refresh)
    except TokenError:
        raise AuthenticationError("Invalid or expired refresh token")

    expires_at = timezone.now() + settings.SIMPLE_JWT.get(
        "ACCESS_TOKEN_LIFETIME", timedelta(hours=6)
    )
    bundle: dict[str, Any] = {
        "access_token": new_access,
        "expires_at": expires_at.isoformat(),
    }
    if rotated:
        bundle["refresh_token"] = rotated
    return bundle


def build_discovery(*, base_url: str) -> dict[str, Any]:
    """RFC 8414 authorization-server metadata for the bridge's discovery."""
    root = base_url.rstrip("/")
    return {
        "issuer": root + "/",
        "authorization_endpoint": root + "/oauth/authorize",
        "token_endpoint": root + "/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": sorted(OAUTH_KNOWN_SCOPES),
        "token_endpoint_auth_methods_supported": ["none"],
    }
