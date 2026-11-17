from __future__ import annotations

from unittest import mock

from asgiref.sync import async_to_sync
from django.test import TestCase, override_settings

from apps.accounts import oauth_social
from apps.accounts.models import User
from apps.accounts.oauth_social import (
    AuthStateError,
    ProviderUnavailableError,
    SocialOAuthService,
    build_authorize_url,
    sign_state,
    verify_state,
)
from apps.common.exceptions import AuthenticationError, ConflictError

GOOGLE_ON = dict(
    OAUTH_GOOGLE_ENABLED=True,
    GOOGLE_CLIENT_ID="google-client",
    GOOGLE_CLIENT_SECRET="google-secret",
)
GITHUB_ON = dict(
    OAUTH_GITHUB_ENABLED=True,
    GITHUB_CLIENT_ID="github-client",
    GITHUB_CLIENT_SECRET="github-secret",
)


class SignedStateTests(TestCase):
    def test_roundtrip_accepts_matching_state(self):
        state = sign_state("google", "https://app.example/cb")
        verify_state("google", "https://app.example/cb", state)  # no raise

    def test_rejects_tampered_signature(self):
        state = sign_state("google", "https://app.example/cb")
        tampered = state[:-3] + ("aaa" if not state.endswith("aaa") else "bbb")
        with self.assertRaises(AuthStateError):
            verify_state("google", "https://app.example/cb", tampered)

    def test_rejects_mismatched_redirect(self):
        state = sign_state("google", "https://app.example/cb")
        with self.assertRaises(AuthStateError):
            verify_state("google", "https://evil.example/cb", state)

    def test_rejects_expired_state(self):
        with mock.patch.object(oauth_social.time, "time", return_value=1000):
            state = sign_state("google", "https://app.example/cb")
        with mock.patch.object(oauth_social.time, "time", return_value=1000 + 601):
            with self.assertRaises(AuthStateError):
                verify_state("google", "https://app.example/cb", state)

    def test_rejects_missing_state(self):
        with self.assertRaises(AuthStateError):
            verify_state("google", "https://app.example/cb", "")


class ProviderConfigTests(TestCase):
    @override_settings(OAUTH_GOOGLE_ENABLED=False)
    def test_disabled_provider_is_unavailable(self):
        with self.assertRaises(ProviderUnavailableError):
            build_authorize_url("google", "https://app.example/cb")

    @override_settings(**GOOGLE_ON)
    def test_enabled_provider_returns_verifiable_url(self):
        url, state = build_authorize_url("google", "https://app.example/cb")
        self.assertIn("accounts.google.com", url)
        self.assertIn("state=", url)
        verify_state("google", "https://app.example/cb", state)

    def test_unknown_provider_is_unavailable(self):
        with self.assertRaises(ProviderUnavailableError):
            build_authorize_url("myspace", "https://app.example/cb")


class ResolveUserTests(TestCase):
    def _identity(self, **over):
        base = {
            "provider_user_id": "12345",
            "email": "new@example.com",
            "first_name": "Ada",
            "last_name": "Lovelace",
        }
        base.update(over)
        return base

    def test_creates_social_user_without_password(self):
        user = oauth_social._resolve_user("github", self._identity())
        self.assertEqual(user.auth_provider, "github")
        self.assertEqual(user.provider_user_id, "12345")
        self.assertTrue(user.is_email_verified)
        self.assertFalse(user.has_usable_password())
        self.assertIsNone(user.vault)
        self.assertEqual(user.auth_methods, {"oauth_github"})

    def test_finds_existing_by_provider_user_id(self):
        first = oauth_social._resolve_user("github", self._identity())
        again = oauth_social._resolve_user("github", self._identity())
        self.assertEqual(first.pk, again.pk)
        self.assertEqual(User.objects.count(), 1)

    def test_links_existing_email_account_and_keeps_password(self):
        existing = User.objects.create_user(
            first_name="Old", last_name="User", email="taken@example.com", password="password123"
        )
        existing.is_email_verified = True
        existing.save()

        linked = oauth_social._resolve_user(
            "github", self._identity(email="taken@example.com")
        )

        self.assertEqual(linked.pk, existing.pk)
        self.assertTrue(linked.has_usable_password())
        self.assertEqual(linked.auth_methods, {"password", "oauth_github"})

    def test_linked_account_signs_in_by_social_identity(self):
        existing = User.objects.create_user(
            first_name="Old", last_name="User", email="taken@example.com", password="password123"
        )
        oauth_social._resolve_user("github", self._identity(email="taken@example.com"))
        again = oauth_social._resolve_user("github", self._identity(email="taken@example.com"))
        self.assertEqual(again.pk, existing.pk)
        self.assertEqual(User.objects.count(), 1)


class ExchangeAndLoginTests(TestCase):
    @override_settings(**GOOGLE_ON)
    def test_google_exchange_issues_tokens_and_no_vault(self):
        identity = {
            "provider_user_id": "g-1",
            "email": "social@example.com",
            "first_name": "Grace",
            "last_name": "Hopper",
        }
        with mock.patch.object(oauth_social, "_google_identity", return_value=identity):
            state = sign_state("google", "https://app.example/cb")
            user, tokens, expires_at, key_salt = async_to_sync(
                SocialOAuthService.exchange_and_login
            )(
                provider="google",
                code="auth-code",
                redirect_uri="https://app.example/cb",
                state=state,
            )

        self.assertEqual(user.email, "social@example.com")
        self.assertEqual(user.auth_provider, "google")
        self.assertIsNone(key_salt)
        self.assertIsInstance(expires_at, str)
        self.assertIn("access", tokens)
        self.assertIn("refresh", tokens)

    @override_settings(**GOOGLE_ON)
    def test_exchange_rejects_bad_state_before_network(self):
        with mock.patch.object(oauth_social, "_google_identity") as exchange:
            with self.assertRaises(AuthStateError):
                async_to_sync(SocialOAuthService.exchange_and_login)(
                    provider="google",
                    code="auth-code",
                    redirect_uri="https://app.example/cb",
                    state="not-a-real-state",
                )
            exchange.assert_not_called()

    @override_settings(OAUTH_GOOGLE_ENABLED=False)
    def test_exchange_fails_closed_when_provider_disabled(self):
        with self.assertRaises(ProviderUnavailableError):
            async_to_sync(SocialOAuthService.exchange_and_login)(
                provider="google",
                code="auth-code",
                redirect_uri="https://app.example/cb",
                state=sign_state("google", "https://app.example/cb"),
            )

    @override_settings(**GITHUB_ON)
    def test_unverified_email_is_rejected(self):
        with mock.patch.object(
            oauth_social, "_github_identity", side_effect=AuthenticationError("no verified email")
        ):
            with self.assertRaises(AuthenticationError):
                async_to_sync(SocialOAuthService.exchange_and_login)(
                    provider="github",
                    code="auth-code",
                    redirect_uri="https://app.example/cb",
                    state=sign_state("github", "https://app.example/cb"),
                )


class TokenClaimsTests(TestCase):
    def test_tokens_carry_connect_claims(self):
        from rest_framework_simplejwt.tokens import AccessToken

        user = User.objects.create_user(
            first_name="Claim", last_name="User", email="claim@example.com", password="password123"
        )
        access = user.tokens()["access"]
        payload = AccessToken(access)
        self.assertEqual(payload["sub"], str(user.id))
        self.assertEqual(payload["principal_type"], "human")
        self.assertEqual(payload["claims_version"], 1)
        self.assertIn("jti", payload)
        self.assertIsNone(payload["on_behalf_of"])


class OAuthEndpointTests(TestCase):
    @override_settings(**GOOGLE_ON)
    def test_authorize_endpoint_returns_url_and_state(self):
        resp = self.client.get(
            "/api/auth/oauth/google/authorize/",
            {"redirect_uri": "https://app.example/cb"},
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()
        self.assertEqual(body["status"], "success")
        self.assertIn("accounts.google.com", body["data"]["authorize_url"])
        self.assertTrue(body["data"]["state"])

    @override_settings(OAUTH_GOOGLE_ENABLED=False)
    def test_authorize_endpoint_fails_closed_when_disabled(self):
        resp = self.client.get(
            "/api/auth/oauth/google/authorize/",
            {"redirect_uri": "https://app.example/cb"},
        )
        self.assertEqual(resp.status_code, 503, resp.content)
        body = resp.json()
        self.assertEqual(body["status"], "failure")
        self.assertIn("not available", body["message"])

    @override_settings(**GOOGLE_ON)
    def test_exchange_endpoint_validates_response_schema(self):
        user = oauth_social._resolve_user(
            "google",
            {
                "provider_user_id": "g-http",
                "email": "http@example.com",
                "first_name": "Http",
                "last_name": "User",
            },
        )
        tokens = {"access": "a", "refresh": "r"}
        with mock.patch.object(
            SocialOAuthService, "exchange_and_login",
            new=mock.AsyncMock(return_value=(user, tokens, "2026-10-30T00:00:00Z", None)),
        ):
            resp = self.client.post(
                "/api/auth/oauth/google/exchange/",
                data={
                    "code": "c",
                    "redirect_uri": "https://app.example/cb",
                    "state": sign_state("google", "https://app.example/cb"),
                },
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()["data"]
        self.assertEqual(body["access"], "a")
        self.assertIsNone(body["vault"])
        self.assertIsNone(body["key_salt"])
        self.assertEqual(body["user"]["email"], "http@example.com")

