"""The account summary drives the web email-change flow.

It must report the database's verification and OPAQUE flags, not a signed hint,
so a browser never skips the re-enrollment step and strands an enrolled account.
"""
from __future__ import annotations

from django.test import TestCase
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User


class MeEndpointTests(TestCase):
    def token(self, user: User) -> str:
        return str(RefreshToken.for_user(user).access_token)

    def make_user(self, email: str) -> User:
        return User.objects.create_user(
            email=email,
            password="Password123!",
            first_name="Account",
            last_name="Settings",
        )

    def test_password_account_reports_both_flags_false(self):
        user = self.make_user("me-password@example.com")
        res = self.client.get(
            "/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {self.token(user)}"
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()["data"]
        self.assertEqual(data["email"], "me-password@example.com")
        self.assertFalse(data["email_verified"])
        self.assertFalse(data["opaque_enrolled"])

    def test_opaque_account_reports_both_flags_true(self):
        user = self.make_user("me-opaque@example.com")
        user.is_email_verified = True
        user.opaque_record = "server-side-registration-record"
        user.opaque_registered_at = timezone.now()
        user.save(
            update_fields=[
                "is_email_verified",
                "opaque_record",
                "opaque_registered_at",
            ]
        )
        res = self.client.get(
            "/api/auth/me/", HTTP_AUTHORIZATION=f"Bearer {self.token(user)}"
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()["data"]
        self.assertTrue(data["email_verified"])
        self.assertTrue(data["opaque_enrolled"])
