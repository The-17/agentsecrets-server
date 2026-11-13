"""Email verification: signup issues a code, the code is single-use, and the
gate stays off until the operator turns it on.

Delivery is patched, never sent. Tests run with DEBUG=True so a missing Brevo
key does not hard-fail the happy paths; the fail-closed case overrides DEBUG.
"""
from __future__ import annotations

from unittest.mock import patch

from datetime import timedelta

from asgiref.sync import async_to_sync
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.accounts.email_challenges import issue
from apps.accounts.models import (
    EmailChallengePurpose,
    OneTimePassword,
    User,
)
from apps.accounts.schemas import RegisterSchema
from apps.accounts.services import AccountService
from apps.common.exceptions import AuthenticationError, RequestError

SEND = "apps.common.email.brevo.send"


def make_user(email: str = "new@example.com") -> User:
    return User.objects.create_user(
        first_name="A",
        last_name="B",
        email=email,
        password="test-password-123",
    )


def register_payload(email: str = "new@example.com") -> RegisterSchema:
    return RegisterSchema(
        first_name="A",
        last_name="B",
        email=email,
        password="test-password-123",
        key_salt="salt-value",
        terms_agreement=True,
    )


class EmailVerificationTests(TestCase):
    """An unverified account must prove control of its address."""

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True, DEBUG=True)
    def test_signup_issues_a_verification_code(self):
        with patch(SEND, return_value=True) as send:
            result = async_to_sync(AccountService.register_user)(
                data=register_payload("signup@example.com")
            )

        challenge = OneTimePassword.objects.get(user__email="signup@example.com")
        self.assertEqual(challenge.purpose, EmailChallengePurpose.VERIFY_EMAIL)
        self.assertEqual(challenge.email, "signup@example.com")
        self.assertIsNotNone(challenge.expires_at)
        self.assertTrue(result["email_verification_required"])
        self.assertEqual(send.call_args.kwargs["to"], "signup@example.com")
        self.assertIn(challenge.code, send.call_args.kwargs["text"])

    @override_settings(REQUIRE_EMAIL_VERIFICATION=False, DEBUG=True)
    def test_signup_issues_nothing_when_gate_is_off(self):
        with patch(SEND, return_value=True) as send:
            async_to_sync(AccountService.register_user)(data=register_payload())

        self.assertFalse(OneTimePassword.objects.exists())
        send.assert_not_called()

    @override_settings(DEBUG=True)
    def test_correct_code_verifies_and_burns_the_challenge(self):
        user = make_user()
        async_to_sync(issue)(
            user=user,
            email=user.email,
            purpose=EmailChallengePurpose.VERIFY_EMAIL,
            subject="Verify",
            body="Code {code}",
        )
        code = OneTimePassword.objects.get(user=user).code

        with patch(SEND, return_value=True):
            async_to_sync(AccountService.verify_email)(email=user.email, otp=int(code))

        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        self.assertFalse(OneTimePassword.objects.filter(user=user).exists())

    @override_settings(DEBUG=True, EMAIL_CODE_MAX_ATTEMPTS=2)
    def test_wrong_codes_count_and_then_lock(self):
        user = make_user()
        with patch(SEND, return_value=True):
            async_to_sync(issue)(
                user=user,
                email=user.email,
                purpose=EmailChallengePurpose.VERIFY_EMAIL,
                subject="Verify",
                body="Code {code}",
            )
        code = OneTimePassword.objects.get(user=user).code
        wrong = (int(code) + 1) % 1_000_000
        for _ in range(2):
            with self.assertRaises(AuthenticationError):
                async_to_sync(AccountService.verify_email)(
                    email=user.email, otp=wrong
                )
        user.refresh_from_db()
        self.assertFalse(user.is_email_verified)
        with self.assertRaises(AuthenticationError):
            async_to_sync(AccountService.verify_email)(email=user.email, otp=int(code))

    @override_settings(DEBUG=True)
    def test_expired_code_is_refused(self):
        user = make_user()
        with patch(SEND, return_value=True):
            async_to_sync(issue)(
                user=user,
                email=user.email,
                purpose=EmailChallengePurpose.VERIFY_EMAIL,
                subject="Verify",
                body="Code {code}",
            )
        challenge = OneTimePassword.objects.get(user=user)
        challenge.expires_at = timezone.now() - timedelta(minutes=1)
        challenge.save(update_fields=["expires_at"])

        with self.assertRaises(AuthenticationError):
            async_to_sync(AccountService.verify_email)(
                email=user.email, otp=int(challenge.code)
            )
        user.refresh_from_db()
        self.assertFalse(user.is_email_verified)

    @override_settings(DEBUG=True)
    def test_email_change_code_cannot_verify_signup(self):
        user = make_user()
        with patch(SEND, return_value=True):
            async_to_sync(issue)(
                user=user,
                email="other@example.com",
                purpose=EmailChallengePurpose.EMAIL_CHANGE,
                subject="Change",
                body="Code {code}",
            )
        code = OneTimePassword.objects.get(user=user).code

        with self.assertRaises(AuthenticationError):
            async_to_sync(AccountService.verify_email)(email=user.email, otp=int(code))
        user.refresh_from_db()
        self.assertFalse(user.is_email_verified)

    @override_settings(DEBUG=True)
    def test_resend_otp_sends_a_fresh_code(self):
        user = make_user()
        with patch(SEND, return_value=True) as send:
            async_to_sync(issue)(
                user=user,
                email=user.email,
                purpose=EmailChallengePurpose.VERIFY_EMAIL,
                subject="Verify",
                body="Code {code}",
            )
            async_to_sync(AccountService.resend_otp)(email=user.email)

        second = OneTimePassword.objects.get(user=user).code
        self.assertEqual(send.call_count, 2)
        self.assertEqual(len(second), 6)
        self.assertEqual(OneTimePassword.objects.get(user=user).attempts, 0)

    @override_settings(DEBUG=True)
    def test_code_with_leading_zero_survives_a_json_number(self):
        user = make_user("zero@example.com")
        with patch(SEND, return_value=True):
            async_to_sync(issue)(
                user=user,
                email=user.email,
                purpose=EmailChallengePurpose.VERIFY_EMAIL,
                subject="Verify",
                body="Code {code}",
            )
        challenge = OneTimePassword.objects.get(user=user)
        challenge.code = "004321"
        challenge.save(update_fields=["code"])

        async_to_sync(AccountService.verify_email)(email=user.email, otp=4321)
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True, DEBUG=False)
    def test_undelivered_mail_fails_closed(self):
        with patch(SEND, return_value=False):
            with self.assertRaises(RequestError):
                async_to_sync(AccountService.register_user)(
                    data=register_payload("undelivered@example.com")
                )
        self.assertFalse(
            OneTimePassword.objects.filter(user__email="undelivered@example.com").exists()
        )
