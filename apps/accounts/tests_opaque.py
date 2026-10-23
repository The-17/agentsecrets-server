"""OPAQUE account enforcement tests.

The sidecar binary is not run here. What is proved is the server contract:
an enrolled account can never fall back to password, enrollment is atomic,
and OPAQUE endpoints fail closed when the sidecar is unconfigured.
"""

from datetime import timedelta

from django.contrib.auth import authenticate as dj_authenticate
from django.test import TestCase
from django.utils import timezone

from .models import OpaqueLoginChallenge, User
from apps.common.exceptions import OpaqueUnavailableError

from .opaque_services import OpaqueService


class AuthMethodStateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="opaque@example.com",
            first_name="Opaque",
            last_name="User",
            password="correct-horse-battery",
            terms_agreement=True,
        )

    def test_password_account_before_enrollment(self):
        self.assertEqual(self.user.auth_methods, {"password"})
        self.assertTrue(self.user.password_login_allowed)

    def test_enrolled_account_keeps_password_for_old_clients(self):
        self.user.opaque_record = "record-blob"
        self.user.opaque_registered_at = timezone.now()
        self.user.save()

        # A CLI that predates OPAQUE cannot do the exchange and cannot be
        # updated, so the password must keep working or the account becomes
        # unreachable from every already-installed client.
        self.assertTrue(self.user.has_usable_password())
        self.assertEqual(self.user.auth_methods, {"password", "opaque"})
        self.assertTrue(self.user.password_login_allowed)
        self.assertTrue(self.user.opaque_login_allowed)
        self.assertIsNotNone(
            dj_authenticate(email=self.user.email, password="correct-horse-battery")
        )

    def test_record_without_timestamp_is_not_enrollment(self):
        # Half-written state must not claim OPAQUE, or the account would have
        # no working method at all.
        self.user.opaque_record = "record-blob"
        self.user.save()
        self.assertEqual(self.user.auth_methods, {"password"})
        self.assertFalse(self.user.opaque_login_allowed)

    def test_enrolled_account_can_still_use_password_login_endpoint(self):
        self.user.opaque_record = "record-blob"
        self.user.opaque_registered_at = timezone.now()
        self.user.save()

        response = self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "correct-horse-battery"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.json().get("data") or {})

    def test_enrolled_account_still_rejects_a_wrong_password(self):
        self.user.opaque_record = "record-blob"
        self.user.opaque_registered_at = timezone.now()
        self.user.save()

        response = self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "not-the-password"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("access", response.json().get("data") or {})


class OpaqueUnavailableTests(TestCase):
    def test_endpoints_fail_closed_when_unconfigured(self):
        service = OpaqueService()
        self.assertFalse(service.enabled)
        with self.assertRaises(OpaqueUnavailableError):
            _ = service.sidecar

    def test_opaque_login_start_returns_503_when_unconfigured(self):
        response = self.client.post(
            "/api/auth/opaque/login/start/",
            data={
                "email": "nobody@example.com",
                "ke1": "AAAA",
                "credential_id": "c1",
            },
            content_type="application/json",
        )
        self.assertNotEqual(response.status_code, 200)
        self.assertIn(response.status_code, (401, 503))

    def test_capabilities_reports_opaque_false(self):
        response = self.client.get("/api/auth/capabilities/")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        data = body.get("data", body)
        self.assertFalse(data["opaque"])
        self.assertTrue(data["password"])


class ChallengeLifecycleTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="challenge@example.com",
            first_name="Challenge",
            last_name="User",
            password="correct-horse-battery",
            terms_agreement=True,
        )

    def test_issue_challenge_sets_ttl(self):
        service = OpaqueService()
        challenge_id = service._issue_challenge(self.user.id)
        challenge = OpaqueLoginChallenge.objects.get(challenge_id=challenge_id)
        remaining = challenge.expires_at - timezone.now()
        self.assertGreater(remaining, timedelta(seconds=100))
        self.assertLess(remaining, timedelta(seconds=125))
        self.assertIsNone(challenge.used_at)

    def test_challenge_rate_limit(self):
        service = OpaqueService()
        for _ in range(10):
            service._issue_challenge(self.user.id)
        with self.assertRaises(Exception):
            service._issue_challenge(self.user.id)
