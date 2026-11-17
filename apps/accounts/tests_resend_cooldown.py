"""Resend cooldown: server enforces a gap between verification codes and returns
the remaining seconds so the web frontend can show a matching countdown."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.email_challenges import issue
from apps.accounts.models import EmailChallengePurpose, OneTimePassword, User
from apps.accounts.services import AccountService

SEND = "apps.common.email.brevo.send"


def make_user(email="cooldown@example.com"):
    user = User.objects.create_user(
        email=email, password="Password123!", first_name="A", last_name="B"
    )
    return user


@override_settings(DEBUG=True, EMAIL_RESEND_COOLDOWN_SECONDS=60)
class ResendCooldownTests(TestCase):
    def token(self, user):
        return str(RefreshToken.for_user(user).access_token)

    def test_success_returns_retry_after(self):
        user = make_user()
        with patch(SEND, return_value=True):
            res = self.client.post(
                "/api/auth/resend-otp/",
                data={"email": user.email},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.token(user)}",
            )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["data"]["retry_after"], 60)

    def test_second_request_inside_cooldown_is_rate_limited(self):
        user = make_user("cooldown-two@example.com")
        with patch(SEND, return_value=True):
            self.client.post(
                "/api/auth/resend-otp/",
                data={"email": user.email},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.token(user)}",
            )
            res = self.client.post(
                "/api/auth/resend-otp/",
                data={"email": user.email},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.token(user)}",
            )
        self.assertEqual(res.status_code, 429)
        body = res.json()
        self.assertEqual(body["code"], "rate_limited")
        self.assertGreater(body["data"]["retry_after"], 0)
        self.assertLessEqual(body["data"]["retry_after"], 60)

    def test_request_after_cooldown_succeeds(self):
        user = make_user("cooldown-three@example.com")
        with patch(SEND, return_value=True) as send:
            self.client.post(
                "/api/auth/resend-otp/",
                data={"email": user.email},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.token(user)}",
            )
            OneTimePassword.objects.filter(user=user).update(
                created_at=timezone.now() - timedelta(seconds=61)
            )
            res = self.client.post(
                "/api/auth/resend-otp/",
                data={"email": user.email},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.token(user)}",
            )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(send.call_count, 2)

    def test_verified_account_is_not_rate_limited_but_refused(self):
        user = make_user("cooldown-verified@example.com")
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])
        res = self.client.post(
            "/api/auth/resend-otp/",
            data={"email": user.email},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token(user)}",
        )
        self.assertEqual(res.status_code, 422)
