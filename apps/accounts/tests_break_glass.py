"""The OPAQUE_ALLOW_PASSWORD break-glass.

Enrollment clears the password hash, so the default contract is hard: an
enrolled account cannot authenticate by password, and nothing may quietly
change that. These tests pin that the gate is closed by default, that opening
it is loud, and that opening it still cannot conjure a hash that is not there.
"""

from unittest.mock import patch

from django.test import TestCase

from apps.accounts.models import User
from apps.accounts.opaque_gate import opaque_sidecar_password_gate


class OpaqueAllowPasswordTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="breakglass@example.com",
            first_name="Break",
            last_name="Glass",
            password="correct-horse-battery",
            terms_agreement=True,
        )
        self.client.defaults["HTTP_HOST"] = "testserver"

    def enroll(self, keep_password: bool):
        from django.utils import timezone

        self.user.opaque_record = "record-blob"
        self.user.opaque_registered_at = timezone.now()
        if not keep_password:
            self.user.set_unusable_password()
        self.user.save()

    def login(self):
        return self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "correct-horse-battery"},
            content_type="application/json",
        )

    def test_gate_is_closed_by_default(self):
        self.assertFalse(opaque_sidecar_password_gate())

    def test_enrolled_account_cannot_use_password_without_break_glass(self):
        self.enroll(keep_password=True)  # even WITH a hash present
        response = self.login()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["code"], "password_login_disabled")

    def test_break_glass_with_hash_restores_login(self):
        # The recovery window: an operator ran set_password but the sidecar is
        # still down, so OPAQUE login cannot work either.
        self.enroll(keep_password=True)
        with patch.dict("os.environ", {"OPAQUE_ALLOW_PASSWORD": "true"}):
            self.assertTrue(opaque_sidecar_password_gate())
            response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.json().get("data") or {})

    def test_break_glass_cannot_conjure_a_missing_hash(self):
        # The normal enrolled account: the hash is gone. The gate must not
        # pretend otherwise, or the error would lie about what is wrong.
        self.enroll(keep_password=False)
        with patch.dict("os.environ", {"OPAQUE_ALLOW_PASSWORD": "true"}):
            response = self.login()
        self.assertEqual(response.status_code, 401)

    def test_break_glass_does_not_unenroll_the_account(self):
        # The in-memory unsetting of opaque_registered_at must not be persisted,
        # or one break-glass login would silently convert the account.
        self.enroll(keep_password=True)
        with patch.dict("os.environ", {"OPAQUE_ALLOW_PASSWORD": "true"}):
            self.login()
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.opaque_registered_at)
        self.assertIsNotNone(self.user.opaque_record)

    def test_case_insensitive_and_explicitly_off(self):
        for value, expected in [("TRUE", True), ("True", True), ("false", False), ("", False), ("1", False)]:
            with patch.dict("os.environ", {"OPAQUE_ALLOW_PASSWORD": value}):
                self.assertEqual(opaque_sidecar_password_gate(), expected, value)
