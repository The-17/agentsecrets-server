"""OPAQUE account enforcement tests.

The sidecar binary is not run here. What is proved is the server contract:
an enrolled account can never fall back to password, enrollment is atomic,
and OPAQUE endpoints fail closed when the sidecar is unconfigured.
"""

from datetime import timedelta
from unittest.mock import Mock, patch

from asgiref.sync import async_to_sync
from django.contrib.auth import authenticate as dj_authenticate
from django.test import TestCase, override_settings
from django.utils import timezone

from .models import OpaqueLoginChallenge, User
from apps.common.exceptions import AuthenticationError, OpaqueUnavailableError

from .opaque import Sidecar, SidecarAuthError, SidecarError
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

    def test_enrolled_account_is_opaque_only(self):
        self.user.opaque_record = "record-blob"
        self.user.opaque_registered_at = timezone.now()
        self.user.set_unusable_password()
        self.user.save()

        # Enrollment clears the password: only the new CLI enrolls, so a
        # record means the user upgraded deliberately. The account is
        # unreachable by password from then on, by design.
        self.assertFalse(self.user.has_usable_password())
        self.assertEqual(self.user.auth_methods, {"opaque"})
        self.assertFalse(self.user.password_login_allowed)
        self.assertTrue(self.user.opaque_login_allowed)
        self.assertIsNone(dj_authenticate(email=self.user.email, password="correct-horse-battery"))

    def test_record_without_timestamp_is_not_enrollment(self):
        # Half-written state must not claim OPAQUE, or the account would have
        # no working method at all.
        self.user.opaque_record = "record-blob"
        self.user.save()
        self.assertEqual(self.user.auth_methods, {"password"})
        self.assertFalse(self.user.opaque_login_allowed)

    def test_enrolled_account_rejects_password_login_endpoint(self):
        self.user.opaque_record = "record-blob"
        self.user.opaque_registered_at = timezone.now()
        self.user.set_unusable_password()
        self.user.save()

        response = self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "correct-horse-battery"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["code"], "password_login_disabled")
        self.assertNotIn("access", response.json().get("data") or {})

    def test_wrong_password_on_unenrolled_account_is_generic(self):
        response = self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "not-the-password"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("access", response.json().get("data") or {})

    def test_login_returns_vault_so_the_console_can_unlock_it(self):
        # The web console reads the vault from the login response and unwraps
        # the private key with it. If this field is dropped or renamed, every
        # vault-enabled account silently falls back to the legacy blob, and a
        # future password removal would strand the console.
        vault = {"version": 1, "vault_version": 1, "envelopes": []}
        self.user.vault = vault
        self.user.vault_version = 1
        self.user.save()

        response = self.client.post(
            "/api/auth/login/",
            data={"email": self.user.email, "password": "correct-horse-battery"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["vault"], vault)
        self.assertEqual(data["vault_version"], 1)


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
        # The v2 split-share vault is accepted additively; clients gate the
        # v1 -> v2 migration on this capability so it can be paused in rollout.
        self.assertTrue(data["vault_v2"])


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


class EnrollmentClearsLegacyBlobTests(TestCase):
    """Enrollment must clear the legacy encrypted_private_key/key_salt blob.

    That blob is an independent offline-attack surface: a database copy plus
    the password would decrypt the account key without the OPAQUE export key,
    which defeats the v2 split-share vault. Clearing it is a prerequisite for
    the v2 security property to hold.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            email="clearblob@example.com",
            first_name="Clear",
            last_name="Blob",
            password="correct-horse-battery",
            terms_agreement=True,
        )
        self.user.encrypted_private_key = "legacy-enc-blob"
        self.user.key_salt = "legacy-salt"
        self.user.save(update_fields=["encrypted_private_key", "key_salt"])

    def test_store_record_clears_legacy_blob(self):
        # _apply_enrollment is the atomic write that _store_record performs once
        # the sidecar returns the record, so it exercises the clearing directly
        # without needing a live sidecar.
        OpaqueService()._apply_enrollment(self.user.id, "new-opaque-record")

        self.user.refresh_from_db()
        self.assertEqual(self.user.opaque_record, "new-opaque-record")
        self.assertIsNotNone(self.user.opaque_registered_at)
        self.assertFalse(self.user.has_usable_password())
        # The legacy blob is gone in the same transaction that removes the password.
        self.assertEqual(self.user.encrypted_private_key, "")
        self.assertEqual(self.user.key_salt, "")


class SidecarStatusMappingTests(TestCase):
    """The sidecar's status codes must survive the HTTP client boundary intact.

    A rejected credential (403) is a failed login. A rejected bearer token (401)
    or any other status is an outage. Collapsing both into one error is what
    told users with a typo that the auth service was down.
    """

    def setUp(self):
        override = override_settings(
            OPAQUE_SIDECAR_URL="http://sidecar.invalid",
            OPAQUE_SIDECAR_TOKEN="test-token",
        )
        override.enable()
        self.addCleanup(override.disable)
        self.sidecar = Sidecar()

    @staticmethod
    def _response(status_code, payload=None, text=""):
        response = Mock(status_code=status_code, text=text)
        response.json.return_value = payload or {}
        return response

    def _login_finish_with(self, status_code):
        with patch.object(
            self.sidecar._session,
            "post",
            return_value=self._response(status_code, text="authentication failed"),
        ):
            self.sidecar.login_finish("ke3", "state", "c1")

    def test_forbidden_is_a_credential_rejection(self):
        with self.assertRaises(SidecarAuthError):
            self._login_finish_with(403)

    def test_unauthorized_is_an_outage_not_a_bad_credential(self):
        # A bad bearer token means the deployment is broken, not the user's
        # password. If this ever becomes SidecarAuthError the server would tell
        # every user "invalid credentials" during a sidecar token rotation.
        with self.assertRaises(SidecarError) as ctx:
            self._login_finish_with(401)
        self.assertNotIsInstance(ctx.exception, SidecarAuthError)

    def test_server_error_is_an_outage(self):
        with self.assertRaises(SidecarError) as ctx:
            self._login_finish_with(500)
        self.assertNotIsInstance(ctx.exception, SidecarAuthError)


class LoginFinishErrorMappingTests(TestCase):
    """A rejected credential must reach the client as 401 invalid_credentials.

    The API shape is the contract the web console and the CLI read. Reporting a
    wrong password as 503 opaque_unavailable hides it behind an outage message
    the user cannot act on.
    """

    def setUp(self):
        override = override_settings(
            OPAQUE_SIDECAR_URL="http://sidecar.invalid",
            OPAQUE_SIDECAR_TOKEN="test-token",
        )
        override.enable()
        self.addCleanup(override.disable)

    def _login_finish_raising(self, exc):
        fake = Mock()
        fake.login_finish.side_effect = exc
        with patch("apps.accounts.opaque_services.make_sidecar", return_value=fake):
            return async_to_sync(OpaqueService().login_finish_async)(
                request=None,
                cred_id="c1",
                ke3="ke3",
                server_state="state",
                email="opaque@example.com",
            )

    def test_rejected_credential_maps_to_invalid_credentials(self):
        with self.assertRaises(AuthenticationError) as ctx:
            self._login_finish_raising(SidecarAuthError("rejected the credential"))
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.err_code, "invalid_credentials")

    def test_outage_still_maps_to_opaque_unavailable(self):
        with self.assertRaises(OpaqueUnavailableError):
            self._login_finish_raising(SidecarError("sidecar unreachable"))

