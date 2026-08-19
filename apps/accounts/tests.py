from __future__ import annotations

import base64
from cryptography.fernet import Fernet
from nacl.public import PrivateKey
from django.test import TestCase
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
