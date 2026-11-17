from __future__ import annotations

import base64
import hashlib
from urllib.parse import urlparse, parse_qs
from cryptography.fernet import Fernet
from nacl.public import PrivateKey
from django.test import TestCase, override_settings
from apps.accounts.models import User
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipRole


class AccountsAPITests(TestCase):
    def setUp(self):
        super().setUp()
        self.keypair = PrivateKey.generate()
        self.public_key_b64 = base64.b64encode(bytes(self.keypair.public_key)).decode("utf-8")

    def test_register_and_login_flow(self):
        """Test full user registration with key provisioning and subsequent login."""
        reg_payload = {
            "first_name": "Alice",
            "last_name": "Smith",
            "email": "alice@example.com",
            "password": "SecurePassword123!",
            "key_salt": "random_salt_12345",
            "terms_agreement": True,
            "public_key": self.public_key_b64,
            "encrypted_private_key": "enc_priv_key_payload",
        }
        res = self.client.post("/api/auth/register/", data=reg_payload, content_type="application/json")
        self.assertEqual(res.status_code, 201)
        data = res.json()["data"]
        self.assertEqual(data["email"], "alice@example.com")
        self.assertIn("workspace", data)
        self.assertEqual(data["workspace"]["type"], WorkspaceType.PERSONAL)

        # Verify DB records
        user = User.objects.get(email="alice@example.com")
        self.assertTrue(user.check_password("SecurePassword123!"))
        self.assertEqual(Membership.objects.filter(user=user, role=MembershipRole.OWNER).count(), 1)

        # Login
        login_payload = {
            "email": "alice@example.com",
            "password": "SecurePassword123!",
        }
        login_res = self.client.post("/api/auth/login/", data=login_payload, content_type="application/json")
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.json()["data"]
        self.assertIn("access", login_data)
        self.assertIn("refresh", login_data)
        self.assertEqual(login_data["user"]["email"], "alice@example.com")
        self.assertEqual(len(login_data["workspaces"]), 1)

    def test_public_key_retrieval(self):
        """Test retrieving public key by email."""
        User.objects.create_user(
            email="bob@example.com",
            password="BobPassword123!",
            first_name="Bob",
            last_name="Jones",
            public_key=self.public_key_b64,
        )

        res = self.client.get("/api/users/bob@example.com/public-key/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["public_key"], self.public_key_b64)

    def test_argon2_password_hashing_on_registration(self):
        """Verify that newly registered users receive Argon2id hashes."""
        reg_payload = {
            "first_name": "Charlie",
            "last_name": "Brown",
            "email": "charlie@example.com",
            "password": "StrongPassword999!",
            "key_salt": "salt_charlie_123",
            "terms_agreement": True,
            "public_key": self.public_key_b64,
            "encrypted_private_key": "enc_priv_charlie",
        }
        res = self.client.post("/api/auth/register/", data=reg_payload, content_type="application/json")
        self.assertEqual(res.status_code, 201)

        user = User.objects.get(email="charlie@example.com")
        self.assertTrue(user.password.startswith("argon2"), f"Expected Argon2 hash, got: {user.password[:15]}")
        self.assertTrue(user.check_password("StrongPassword999!"))

    def test_pbkdf2_passive_rehash_migration(self):
        """
        Verify that existing users with legacy PBKDF2 hashes can log in seamlessly
        and are passively upgraded to Argon2id without forced password resets.
        """
        from django.contrib.auth.hashers import make_password
        legacy_hash = make_password("LegacyPassword123!", hasher="pbkdf2_sha256")
        self.assertTrue(legacy_hash.startswith("pbkdf2_sha256$"))

        user = User.objects.create(
            email="legacy@example.com",
            password=legacy_hash,
            first_name="Legacy",
            last_name="User",
            public_key=self.public_key_b64,
        )

        login_res = self.client.post("/api/auth/login/", data={
            "email": "legacy@example.com",
            "password": "LegacyPassword123!",
        }, content_type="application/json")
        self.assertEqual(login_res.status_code, 200)

        # Refresh from database and verify hash was upgraded to Argon2id
        user.refresh_from_db()
        self.assertTrue(user.password.startswith("argon2"), f"Expected passive upgrade to Argon2, got: {user.password[:15]}")
        self.assertTrue(user.check_password("LegacyPassword123!"))

    def test_unicode_nfkc_normalization(self):
        """Verify that decomposed and precomposed Unicode glyphs authenticate identically."""
        import unicodedata
        composed = "P\u00e1ssw\u00f6rd123!"     # "Pásswörd123!" precomposed
        decomposed = unicodedata.normalize("NFD", composed)  # Decomposed bytes

        reg_payload = {
            "first_name": "Unicode",
            "last_name": "Tester",
            "email": "unicode@example.com",
            "password": decomposed,
            "key_salt": "salt_unicode_123",
            "terms_agreement": True,
            "public_key": self.public_key_b64,
            "encrypted_private_key": "enc_priv_unicode",
        }
        res = self.client.post("/api/auth/register/", data=reg_payload, content_type="application/json")
        self.assertEqual(res.status_code, 201)

        # Login with precomposed variant
        login_res = self.client.post("/api/auth/login/", data={
            "email": "unicode@example.com",
            "password": composed,
        }, content_type="application/json")
        self.assertEqual(login_res.status_code, 200)

    def test_null_byte_password_rejection(self):
        """Verify that passwords containing null bytes are rejected with 422."""
        reg_payload = {
            "first_name": "Hacker",
            "last_name": "Null",
            "email": "nullbyte@example.com",
            "password": "BadPassword\x00Injected!",
            "key_salt": "salt_null_123",
            "terms_agreement": True,
            "public_key": self.public_key_b64,
            "encrypted_private_key": "enc_priv_null",
        }
        res = self.client.post("/api/auth/register/", data=reg_payload, content_type="application/json")
        self.assertEqual(res.status_code, 422)

    def test_security_headers_injected(self):
        """Verify that production security headers are present on all responses."""
        res = self.client.get("/api/users/nonexistent@example.com/public-key/")
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("max-age=31536000", res.headers.get("Strict-Transport-Security", ""))

        # Auth route must have Cache-Control: no-store
        auth_res = self.client.post("/api/auth/login/", data={
            "email": "test@example.com",
            "password": "randompassword123",
        }, content_type="application/json")
        self.assertIn("no-store", auth_res.headers.get("Cache-Control", ""))

    def test_token_refresh_flow(self):
        """Verify token refresh endpoint functions correctly with rotation."""
        reg_payload = {
            "first_name": "Refresher",
            "last_name": "User",
            "email": "refresher@example.com",
            "password": "RefreshPassword123!",
            "key_salt": "salt_refresh_123",
            "terms_agreement": True,
            "public_key": self.public_key_b64,
            "encrypted_private_key": "enc_priv_refresh",
        }
        self.client.post("/api/auth/register/", data=reg_payload, content_type="application/json")

        login_res = self.client.post("/api/auth/login/", data={
            "email": "refresher@example.com",
            "password": "RefreshPassword123!",
        }, content_type="application/json")
        self.assertEqual(login_res.status_code, 200)
        refresh_token = login_res.json()["data"]["refresh"]

        # Call refresh endpoint
        refresh_res = self.client.post("/api/auth/refresh/", data={
            "refresh": refresh_token,
        }, content_type="application/json")
        self.assertEqual(refresh_res.status_code, 200)
        refresh_data = refresh_res.json()["data"]
        self.assertIn("access", refresh_data)
        self.assertIn("refresh", refresh_data)
        self.assertIn("expires_at", refresh_data)

    def test_stateless_jwt_auth_no_database_queries(self):
        """
        Verify that validating a JWT with embedded claims executes 0 database queries.
        """
        from apps.accounts.auth import StatelessJWTAuthentication
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        user = User.objects.create_user(
            email="stateless@example.com",
            password="StatelessPassword123!",
            first_name="Stateless",
            last_name="User",
            public_key=self.public_key_b64,
        )
        tokens = user.tokens()
        access_token = tokens["access"]

        auth_validator = StatelessJWTAuthentication()
        validated_token = auth_validator.get_validated_token(access_token)

        # Assert 0 database queries are executed when resolving the authenticated user
        with CaptureQueriesContext(connection) as queries:
            principal = auth_validator.get_user(validated_token)
            self.assertEqual(len(queries), 0, f"Expected 0 database queries, got {len(queries)}: {queries}")

        self.assertEqual(principal.email, "stateless@example.com")
        self.assertEqual(principal.first_name, "Stateless")
        self.assertEqual(str(principal.id), str(user.id))
        self.assertTrue(principal.is_authenticated)


def _pkce_pair(verifier: str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") -> tuple[str, str]:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class OAuthLoginTests(TestCase):
    """OAuth 2.1 Authorization Code + PKCE for headless agent login."""

    CALLBACK = "http://127.0.0.1:9/callback"

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            email="oauth@example.com",
            password="OauthPassword123!",
            first_name="Olive",
            last_name="Auth",
        )
        _, self.challenge = _pkce_pair()
        self.params = {
            "response_type": "code",
            "client_id": "agentsecrets-mcp",
            "redirect_uri": self.CALLBACK,
            "scope": "read write",
            "state": "teststate123",
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
        }

    def _approve(self, params=None):
        """Run login + approve; return the authorization code."""
        params = params or self.params
        login_res = self.client.post("/oauth/authorize", data={
            **params, "action": "login",
            "email": "oauth@example.com", "password": "OauthPassword123!",
        })
        self.assertEqual(login_res.status_code, 200)
        approve_res = self.client.post("/oauth/authorize", data={
            **params, "action": "approve",
        })
        self.assertEqual(approve_res.status_code, 302)
        location = approve_res["Location"]
        self.assertTrue(location.startswith(self.CALLBACK + "?"), location)
        query = parse_qs(urlparse(location).query)
        self.assertEqual(query.get("state"), ["teststate123"])
        return query["code"][0]

    def _exchange(self, code, verifier=None, redirect_uri=CALLBACK):
        verifier, _ = _pkce_pair() if verifier is None else (verifier, None)
        return self.client.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": "agentsecrets-mcp",
            "code_verifier": verifier,
        }, content_type="application/json")

    def test_discovery_document(self):
        res = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(res.status_code, 200)
        doc = res.json()
        self.assertEqual(doc["token_endpoint"], "http://testserver/oauth/token")
        self.assertEqual(doc["authorization_endpoint"], "http://testserver/oauth/authorize")
        self.assertEqual(doc["response_types_supported"], ["code"])
        self.assertIn("S256", doc["code_challenge_methods_supported"])

    @override_settings(OAUTH_ISSUER_BASE_URL="https://api.example.test")
    def test_discovery_honors_issuer_override(self):
        doc = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(doc["issuer"], "https://api.example.test/")

    def test_authorize_rejects_bad_requests_without_redirect(self):
        # Unknown client
        res = self.client.get("/oauth/authorize", data={**self.params, "client_id": "evil"})
        self.assertEqual(res.status_code, 400)
        # Non-loopback redirect: rendered error, NEVER a redirect to it
        res = self.client.get("/oauth/authorize", data={
            **self.params, "redirect_uri": "https://evil.example/cb",
        })
        self.assertEqual(res.status_code, 400)
        self.assertNotIn("Location", res.headers)
        # Missing PKCE challenge
        res = self.client.get("/oauth/authorize", data={
            k: v for k, v in self.params.items() if k != "code_challenge"
        })
        self.assertEqual(res.status_code, 400)
        # Wrong response type
        res = self.client.get("/oauth/authorize", data={**self.params, "response_type": "token"})
        self.assertEqual(res.status_code, 400)

    def test_full_loopback_flow_mints_working_jwt(self):
        code = self._approve()
        res = self._exchange(code)
        self.assertEqual(res.status_code, 200)
        bundle = res.json()
        # Top-level fields (no {data:} envelope — the bridge reads these directly)
        self.assertIn("access_token", bundle)
        self.assertIn("refresh_token", bundle)
        self.assertIn("expires_at", bundle)
        self.assertIn("no-store", res.headers.get("Cache-Control", ""))
        # The minted access token authenticates a real API call
        me = self.client.get("/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {bundle['access_token']}")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["data"]["email"], "oauth@example.com")

    def test_deny_redirects_with_error(self):
        self.client.post("/oauth/authorize", data={
            **self.params, "action": "login",
            "email": "oauth@example.com", "password": "OauthPassword123!",
        })
        res = self.client.post("/oauth/authorize", data={**self.params, "action": "deny"})
        self.assertEqual(res.status_code, 302)
        query = parse_qs(urlparse(res["Location"]).query)
        self.assertEqual(query.get("error"), ["access_denied"])

    def test_pkce_mismatch_rejected(self):
        code = self._approve()
        res = self._exchange(code, verifier="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.assertEqual(res.status_code, 401)

    def test_code_replay_rejected(self):
        code = self._approve()
        self.assertEqual(self._exchange(code).status_code, 200)
        self.assertEqual(self._exchange(code).status_code, 401)

    def test_code_bound_to_redirect_uri(self):
        code = self._approve()
        res = self._exchange(code, redirect_uri="http://127.0.0.1:10/callback")
        self.assertEqual(res.status_code, 401)

    def test_unknown_code_rejected(self):
        res = self._exchange("not-a-real-code")
        self.assertEqual(res.status_code, 401)

    def test_refresh_grant_rotates(self):
        code = self._approve()
        refresh = self._exchange(code).json()["refresh_token"]
        res = self.client.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": "agentsecrets-mcp",
        }, content_type="application/json")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("access_token", body)
        # Old refresh token was rotated + blacklisted: reuse fails
        again = self.client.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": "agentsecrets-mcp",
        }, content_type="application/json")
        self.assertEqual(again.status_code, 401)

    def test_wrong_password_shows_login_error(self):
        res = self.client.post("/oauth/authorize", data={
            **self.params, "action": "login",
            "email": "oauth@example.com", "password": "WrongPassword123!",
        })
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Invalid email or password", res.content)
