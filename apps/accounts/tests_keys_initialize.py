"""Key initialization for social-sign-up accounts and key material access.

A Google/GitHub account is created with no keypair, workspace, or password
factor. ``POST /auth/keys/initialize/`` sets the keys and creates the personal
workspace once the user picks a master vault password; ``GET /auth/keymaterial/``
returns the ciphertexts an already-authenticated session needs to unlock its
own vault locally.
"""

from __future__ import annotations

import base64

from django.test import TestCase
from nacl.signing import SigningKey

from apps.accounts.models import User
from apps.workspaces.models import Membership, Workspace


def _jwt(client, user: User) -> dict[str, str]:
    tokens = user.tokens()
    return {"HTTP_AUTHORIZATION": f"Bearer {tokens['access']}"}


class InitializeKeysTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            email="social@example.com",
            first_name="Social",
            last_name="User",
            auth_provider="google",
            provider_user_id="g-1",
        )
        self.user.set_unusable_password()
        self.user.save()
        # A real X25519 public key: 32 bytes, base64.
        self.public_key = base64.b64encode(bytes(SigningKey.generate().verify_key)).decode()

    def _payload(self, **overrides):
        payload = {
            "public_key": self.public_key,
            "encrypted_private_key": "encrypted-blob",
            "key_salt": "aabbccdd",
            "password": "master-password-1",
        }
        payload.update(overrides)
        return payload

    def test_initializes_keys_creates_workspace_and_password(self):
        res = self.client.post(
            "/api/auth/keys/initialize/",
            self._payload(),
            content_type="application/json",
            **_jwt(self.client, self.user),
        )
        self.assertEqual(res.status_code, 200, res.content)

        self.user.refresh_from_db()
        self.assertEqual(self.user.public_key, self.public_key)
        self.assertTrue(self.user.has_usable_password())
        self.assertTrue(self.user.check_password("master-password-1"))
        self.assertIn("password", self.user.auth_methods)
        self.assertIn("oauth_google", self.user.auth_methods)

        workspace = Workspace.objects.get(owner=self.user)
        self.assertEqual(workspace.type, "personal")
        membership = Membership.objects.get(user=self.user, workspace=workspace)
        self.assertEqual(membership.role, "owner")
        # Sealed to the public key, so it is not the raw Fernet key.
        self.assertNotEqual(membership.encrypted_workspace_key, "")

    def test_refuses_second_initialization(self):
        self.client.post(
            "/api/auth/keys/initialize/",
            self._payload(),
            content_type="application/json",
            **_jwt(self.client, self.user),
        )
        res = self.client.post(
            "/api/auth/keys/initialize/",
            self._payload(public_key=base64.b64encode(b"x" * 32).decode()),
            content_type="application/json",
            **_jwt(self.client, self.user),
        )
        self.assertEqual(res.status_code, 409)

    def test_password_is_optional(self):
        res = self.client.post(
            "/api/auth/keys/initialize/",
            self._payload(password=None),
            content_type="application/json",
            **_jwt(self.client, self.user),
        )
        self.assertEqual(res.status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.has_usable_password())
        self.assertEqual(self.user.public_key, self.public_key)

    def test_requires_auth(self):
        res = self.client.post(
            "/api/auth/keys/initialize/",
            self._payload(),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 401)

    def test_enrolled_account_refuses_password(self):
        self.user.opaque_record = {"k": "v"}
        self.user.opaque_registered_at = "2026-01-01T00:00:00Z"
        self.user.save()
        res = self.client.post(
            "/api/auth/keys/initialize/",
            self._payload(),
            content_type="application/json",
            **_jwt(self.client, self.user),
        )
        self.assertEqual(res.status_code, 409)
        self.user.refresh_from_db()
        self.assertFalse(self.user.has_usable_password())


class KeyMaterialTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(
            email="keys@example.com",
            first_name="Key",
            last_name="User",
        )
        self.user.set_password("password123")
        self.user.public_key = base64.b64encode(b"p" * 32).decode()
        self.user.encrypted_private_key = "enc-priv"
        from apps.common.services.encryption import EncryptionService as encryption_service
        self.user.key_salt = encryption_service.encrypt("aabbccdd")
        self.user.save()

    def test_returns_ciphertexts_to_own_session(self):
        res = self.client.get("/api/auth/keymaterial/", **_jwt(self.client, self.user))
        self.assertEqual(res.status_code, 200, res.content)
        data = res.json()["data"]
        self.assertEqual(data["public_key"], self.user.public_key)
        self.assertEqual(data["encrypted_private_key"], "enc-priv")
        self.assertEqual(data["key_salt"], "aabbccdd")
        self.assertIsNone(data["vault"])

    def test_social_account_returns_null_material(self):
        social = User.objects.create(
            email="bare@example.com",
            first_name="Bare",
            last_name="User",
            auth_provider="github",
            provider_user_id="gh-1",
        )
        social.set_unusable_password()
        social.save()
        res = self.client.get("/api/auth/keymaterial/", **_jwt(self.client, social))
        self.assertEqual(res.status_code, 200)
        data = res.json()["data"]
        self.assertIsNone(data["public_key"])
        self.assertIsNone(data["encrypted_private_key"])
        self.assertIsNone(data["key_salt"])

    def test_requires_auth(self):
        res = self.client.get("/api/auth/keymaterial/")
        self.assertEqual(res.status_code, 401)
