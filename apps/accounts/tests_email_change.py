from __future__ import annotations

from asgiref.sync import async_to_sync
from django.test import TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import OneTimePassword, User
from apps.accounts.services import AccountService
from apps.common.exceptions import AuthenticationError, ConflictError


class EmailChangeTests(TestCase):
    """Email change is OTP-confirmed against the NEW address.

    Delivery goes through Brevo; with BREVO_API_KEY unset the client is a no-op
    and (outside DEBUG) the flow fails closed. Tests run with DEBUG=True so the
    request stage stores the pending address + code without a real send.

    The service methods are async, so they are driven with async_to_sync; calling
    them bare would return a coroutine and assert nothing.
    """

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(
            first_name="A",
            last_name="B",
            email="old@example.com",
            password="password123",
        )
        self.user.is_email_verified = True
        self.user.save()
        self.other = User.objects.create_user(
            first_name="C",
            last_name="D",
            email="taken@example.com",
            password="password123",
        )

    def _token(self, user: User) -> str:
        return str(RefreshToken.for_user(user).access_token)

    @override_settings(DEBUG=True)
    def test_request_stores_pending_and_code(self):
        async_to_sync(AccountService.request_email_change)(
            user=self.user, new_email="new@example.com"
        )

        self.user.refresh_from_db()
        self.assertEqual(self.user.pending_email, "new@example.com")
        otp = OneTimePassword.objects.get(user=self.user)
        self.assertEqual(len(otp.code), 6)

    @override_settings(DEBUG=True)
    def test_confirm_swaps_email_and_clears_pending(self):
        async_to_sync(AccountService.request_email_change)(
            user=self.user, new_email="new@example.com"
        )
        otp = OneTimePassword.objects.get(user=self.user)

        async_to_sync(AccountService.confirm_email_change)(
            user=self.user, new_email="new@example.com", otp=int(otp.code)
        )

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "new@example.com")
        self.assertTrue(self.user.is_email_verified)
        self.assertIsNone(self.user.pending_email)
        self.assertFalse(OneTimePassword.objects.filter(user=self.user).exists())

    @override_settings(DEBUG=True)
    def test_request_rejects_existing_email(self):
        with self.assertRaises(ConflictError):
            async_to_sync(AccountService.request_email_change)(
                user=self.user, new_email="taken@example.com"
            )

    @override_settings(DEBUG=True)
    def test_confirm_rejects_wrong_code(self):
        async_to_sync(AccountService.request_email_change)(
            user=self.user, new_email="new@example.com"
        )
        with self.assertRaises(AuthenticationError):
            async_to_sync(AccountService.confirm_email_change)(
                user=self.user, new_email="new@example.com", otp=111111
            )

    def test_route_requires_jwt(self):
        # No auth header: the JWTAuth wall must reject.
        resp = self.client.post(
            "/api/auth/update-email/",
            data={"new_email": "x@example.com"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)

    @override_settings(DEBUG=True)
    def test_route_end_to_end_with_jwt(self):
        token = self._token(self.user)
        resp = self.client.post(
            "/api/auth/update-email/",
            data={"new_email": "new@example.com"},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(resp.status_code, 200)

        otp = OneTimePassword.objects.get(user=self.user)
        resp2 = self.client.post(
            "/api/auth/update-email/confirm/",
            data={"new_email": "new@example.com", "otp": int(otp.code)},
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(resp2.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "new@example.com")
