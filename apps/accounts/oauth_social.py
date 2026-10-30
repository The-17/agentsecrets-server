"""Google and GitHub social sign-in / sign-up (v4 identity providers).

Design constraints, in order of importance:

1. Fail closed. An unconfigured provider returns 503, never a password fallback.
   An unverified provider email is rejected, never trusted.
2. Identity-only. A social login issues the same JWT pair as password login but
   carries no vault material: ``vault``/``key_salt``/``encrypted_private_key``
   stay null because the user never proved possession of a vault key.
3. No silent account linking. The User model has a single ``auth_provider``
   column, so re-pointing an existing password account at Google or GitHub
   would drop its password method. Instead, an email that is already registered
   raises a conflict telling the user to sign in with the existing method.

Only ``requests`` is used (already a dependency); the token/userinfo calls are
plain HTTPS and run off the event loop via ``sync_to_async``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import requests
from asgiref.sync import sync_to_async
from django.conf import settings
from django.utils import timezone

from apps.common.exceptions import AuthenticationError, ConflictError
from .models import User
from .selectors import AccountSelector

logger = logging.getLogger("apps.accounts")

HTTP_TIMEOUT_SECONDS = 10
STATE_MAX_AGE_SECONDS = 600
STATE_FIELD_SEP = "|"


class AuthStateError(AuthenticationError):
    """The OAuth ``state`` is missing, tampered with, or stale."""


class ProviderUnavailableError(AuthenticationError):
    """The provider is disabled or its client credentials are not configured."""


_PROVIDERS: dict[str, dict[str, Any]] = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
        "client_id": lambda: settings.GOOGLE_CLIENT_ID,
        "client_secret": lambda: settings.GOOGLE_CLIENT_SECRET,
        "enabled": lambda: bool(
            getattr(settings, "OAUTH_GOOGLE_ENABLED", False)
            and getattr(settings, "GOOGLE_CLIENT_ID", "")
            and getattr(settings, "GOOGLE_CLIENT_SECRET", "")
        ),
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scope": "read:user user:email",
        "client_id": lambda: settings.GITHUB_CLIENT_ID,
        "client_secret": lambda: settings.GITHUB_CLIENT_SECRET,
        "enabled": lambda: bool(
            getattr(settings, "OAUTH_GITHUB_ENABLED", False)
            and getattr(settings, "GITHUB_CLIENT_ID", "")
            and getattr(settings, "GITHUB_CLIENT_SECRET", "")
        ),
    },
}


def provider_config(provider: str) -> dict[str, Any]:
    """Return the provider config, refusing unknown or disabled providers."""
    config = _PROVIDERS.get(provider)
    if config is None:
        raise ProviderUnavailableError(f"Unknown identity provider: {provider}")
    if not config["enabled"]():
        raise ProviderUnavailableError(f"Provider {provider} is not configured")
    return config


# ---------------------------------------------------------------------------
# Signed state (CSRF / replay guard)
# ---------------------------------------------------------------------------

def sign_state(provider: str, redirect_uri: str) -> str:
    """Create a tamper-evident ``state`` bound to provider and redirect_uri.

    The payload carries its own timestamp, so verification recomputes the MAC
    over the exact bytes that were signed instead of re-signing with a fresh
    clock (which would never match).
    """
    payload = STATE_FIELD_SEP.join(
        [provider, redirect_uri, secrets.token_urlsafe(24), str(int(time.time()))]
    )
    signature = hmac.new(
        settings.SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    raw = f"{payload}{STATE_FIELD_SEP}{signature}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_state(provider: str, redirect_uri: str, state: str) -> None:
    """Raise :class:`AuthStateError` unless ``state`` is ours, fresh, and matches."""
    if not state:
        raise AuthStateError("Missing OAuth state")
    try:
        raw = base64.urlsafe_b64decode(state.encode()).decode()
        payload, signature = raw.rsplit(STATE_FIELD_SEP, 1)
    except Exception as exc:  # malformed base64 / missing separator
        raise AuthStateError("Malformed OAuth state") from exc

    expected = hmac.new(
        settings.SECRET_KEY.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise AuthStateError("Invalid OAuth state signature")

    parts = payload.split(STATE_FIELD_SEP)
    if len(parts) != 4:
        raise AuthStateError("Malformed OAuth state payload")
    signed_provider, signed_redirect, _nonce, issued_at = parts
    if signed_provider != provider or signed_redirect != redirect_uri:
        raise AuthStateError("OAuth state does not match this request")
    try:
        age = time.time() - int(issued_at)
    except ValueError as exc:
        raise AuthStateError("Malformed OAuth state timestamp") from exc
    if age < 0 or age > STATE_MAX_AGE_SECONDS:
        raise AuthStateError("OAuth state has expired")


# ---------------------------------------------------------------------------
# Authorize URL
# ---------------------------------------------------------------------------

def build_authorize_url(provider: str, redirect_uri: str) -> tuple[str, str]:
    """Return ``(authorize_url, state)`` for the client to open and store."""
    config = provider_config(provider)
    state = sign_state(provider, redirect_uri)
    params = {
        "response_type": "code",
        "client_id": config["client_id"](),
        "redirect_uri": redirect_uri,
        "scope": config["scope"],
        "state": state,
    }
    return f"{config['authorize_url']}?{urlencode(params)}", state


# ---------------------------------------------------------------------------
# Provider HTTP exchanges (synchronous; called via sync_to_async)
# ---------------------------------------------------------------------------

def _google_identity(code: str, redirect_uri: str) -> dict[str, Any]:
    config = _PROVIDERS["google"]
    token_resp = requests.post(
        config["token_url"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": config["client_id"](),
            "client_secret": config["client_secret"](),
        },
        headers={"Accept": "application/json"},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    token_resp.raise_for_status()
    access_token = token_resp.json().get("access_token")
    if not access_token:
        raise AuthenticationError("Google did not return an access token")

    info_resp = requests.get(
        config["userinfo_url"],
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    info_resp.raise_for_status()
    info = info_resp.json()

    if not info.get("email") or not info.get("email_verified"):
        raise AuthenticationError("Google did not return a verified email")
    if not info.get("sub"):
        raise AuthenticationError("Google did not return a stable subject id")

    return {
        "provider_user_id": str(info["sub"]),
        "email": info["email"],
        "first_name": info.get("given_name") or "",
        "last_name": info.get("family_name") or "",
    }


def _github_identity(code: str, redirect_uri: str) -> dict[str, Any]:
    config = _PROVIDERS["github"]
    token_resp = requests.post(
        config["token_url"],
        data={
            "client_id": config["client_id"](),
            "client_secret": config["client_secret"](),
            "code": code,
            "redirect_uri": redirect_uri,
        },
        headers={"Accept": "application/json"},
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    token_resp.raise_for_status()
    access_token = token_resp.json().get("access_token")
    if not access_token:
        raise AuthenticationError("GitHub did not return an access token")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }
    user_resp = requests.get(
        config["userinfo_url"], headers=headers, timeout=HTTP_TIMEOUT_SECONDS
    )
    user_resp.raise_for_status()
    profile = user_resp.json()

    emails_resp = requests.get(
        config["emails_url"], headers=headers, timeout=HTTP_TIMEOUT_SECONDS
    )
    emails_resp.raise_for_status()
    primary = next(
        (
            entry
            for entry in emails_resp.json()
            if entry.get("primary") and entry.get("verified")
        ),
        None,
    )
    if primary is None:
        raise AuthenticationError("GitHub account has no verified primary email")

    display = (profile.get("name") or profile.get("login") or "").strip()
    first_name, _, last_name = display.partition(" ")
    return {
        "provider_user_id": str(profile["id"]),
        "email": primary["email"],
        "first_name": first_name or profile.get("login") or "User",
        "last_name": last_name,
    }


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------

def _resolve_user(provider: str, identity: dict[str, Any]) -> User:
    """Find the account for this social identity, or create one.

    Runs inside ``sync_to_async``: plain ORM, no awaits.
    """
    user = (
        User.objects.filter(
            auth_provider=provider,
            provider_user_id=identity["provider_user_id"],
        )
        .order_by("created_at")
        .first()
    )
    if user is not None:
        if not user.is_active:
            raise AuthenticationError("Account is inactive")
        return user

    email = identity["email"].strip().lower()
    existing = User.objects.filter(email__iexact=email).first()
    if existing is not None:
        # Do not re-point an existing account: the single auth_provider column
        # would drop its current login method. Ask the user to use it instead.
        raise ConflictError(
            "An account with this email already exists. Sign in with your "
            "existing method, then link this provider from settings."
        )

    user = User(
        email=email,
        first_name=(identity["first_name"] or "User")[:50],
        last_name=(identity["last_name"] or "")[:50],
        auth_provider=provider,
        provider_user_id=identity["provider_user_id"],
        is_email_verified=True,
        terms_agreement=True,
    )
    user.set_unusable_password()
    user.save()
    return user


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class SocialOAuthService:
    @staticmethod
    async def exchange_and_login(
        *, provider: str, code: str, redirect_uri: str, state: str
    ) -> tuple[User, dict[str, Any], str, None]:
        """Complete the code exchange and return login credentials.

        Returns ``(user, tokens, expires_at_iso, key_salt)``. ``key_salt`` is
        always ``None``: a social identity never unlocks the vault.
        """
        provider_config(provider)  # validate before any network call
        verify_state(provider, redirect_uri, state)
        exchange = _google_identity if provider == "google" else _github_identity
        identity = await sync_to_async(exchange, thread_sensitive=True)(
            code, redirect_uri
        )

        user = await sync_to_async(_resolve_user, thread_sensitive=True)(
            provider, identity
        )

        tokens = await sync_to_async(user.tokens, thread_sensitive=True)()
        expires_at = (
            timezone.now()
            + settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME", timedelta(hours=6))
        ).isoformat()

        logger.info(
            "social login provider=%s user=%s created=%s",
            provider,
            user.id,
            user.auth_provider == provider,
        )
        return user, tokens, expires_at, None

    @staticmethod
    async def workspaces(user: User) -> list[dict[str, Any]]:
        return await AccountSelector.get_user_workspaces_data(user=user)
