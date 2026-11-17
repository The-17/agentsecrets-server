"""Soft gates for unverified accounts.

The gates are inert until REQUIRE_EMAIL_VERIFICATION is on. Caps refuse only
the creation that would cross the line; existing data keeps working.
"""
from __future__ import annotations

from asgiref.sync import async_to_sync
from django.test import TestCase, override_settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.accounts.verification import (
    enforce_creation_cap,
    is_verified,
    require_verified_email,
)
from apps.common.exceptions import RequestError


def make_user(email: str = "gate@example.com", verified: bool = False) -> User:
    user = User.objects.create_user(
        first_name="Gate",
        last_name="User",
        email=email,
        password="password123",
    )
    user.is_email_verified = verified
    user.save(update_fields=["is_email_verified"])
    return user


class GateHelperTests(TestCase):
    @override_settings(REQUIRE_EMAIL_VERIFICATION=False)
    def test_gates_are_inert_when_flag_is_off(self):
        user = make_user()
        self.assertTrue(async_to_sync(is_verified)(user))
        async_to_sync(require_verified_email)(user, action="use cloud mode")
        async_to_sync(enforce_creation_cap)(
            user, current=99, adding=1, limit=5, what="secrets"
        )

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_unverified_is_refused_and_names_the_fix(self):
        user = make_user()
        with self.assertRaises(RequestError) as caught:
            async_to_sync(require_verified_email)(user, action="use cloud mode")
        self.assertEqual(caught.exception.err_code, "unverified_user")
        self.assertIn("agentsecrets email verify", caught.exception.err_msg)

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_verified_passes(self):
        user = make_user(verified=True)
        self.assertTrue(async_to_sync(is_verified)(user))
        async_to_sync(require_verified_email)(user, action="use cloud mode")

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_cap_refuses_only_the_creation_that_crosses_it(self):
        user = make_user()

        async_to_sync(enforce_creation_cap)(
            user, current=4, adding=1, limit=5, what="secrets"
        )
        with self.assertRaises(RequestError):
            async_to_sync(enforce_creation_cap)(
                user, current=5, adding=1, limit=5, what="secrets"
            )

        # Grandfathering: an account already above the cap can still update
        # what it has. Only a new creation is refused.
        async_to_sync(enforce_creation_cap)(
            user, current=7, adding=0, limit=5, what="secrets"
        )
        with self.assertRaises(RequestError):
            async_to_sync(enforce_creation_cap)(
                user, current=7, adding=1, limit=5, what="secrets"
            )

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_cap_does_not_apply_to_verified_accounts(self):
        user = make_user(verified=True)
        async_to_sync(enforce_creation_cap)(
            user, current=5, adding=1, limit=5, what="secrets"
        )


class TokenClaimTests(TestCase):
    def test_claim_reflects_the_flag_at_issue_time(self):
        user = make_user()
        import jwt

        access = user.tokens()["access"]
        claims = jwt.decode(access, options={"verify_signature": False})
        self.assertFalse(claims["email_verified"])

        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])
        claims = jwt.decode(
            user.tokens()["access"], options={"verify_signature": False}
        )
        self.assertTrue(claims["email_verified"])


class CloudModeGateTests(TestCase):
    """Creating an agent mints the workload token that cloud mode uses."""

    def setUp(self):
        super().setUp()
        self.user = make_user()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        ws = self.client.post(
            "/api/workspaces/",
            data={"name": "Gate Team", "encrypted_workspace_key": "enc-key"},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(ws.status_code, 201)
        self.workspace_id = ws.json()["data"]["id"]

    def _create_agent(self):
        return self.client.post(
            f"/api/workspaces/{self.workspace_id}/agents/",
            data={"name": "ci-bot"},
            content_type="application/json",
            **self.headers,
        )

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_unverified_cannot_mint_a_cloud_token(self):
        resp = self._create_agent()
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["code"], "unverified_user")

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_verified_can_mint_a_cloud_token(self):
        self.user.is_email_verified = True
        self.user.save(update_fields=["is_email_verified"])
        self.assertEqual(self._create_agent().status_code, 201)

    @override_settings(REQUIRE_EMAIL_VERIFICATION=False)
    def test_flag_off_keeps_todays_behavior(self):
        self.assertEqual(self._create_agent().status_code, 201)


class CreationCapWireTests(TestCase):
    """The caps are wired into the create paths, not just the helper."""

    def setUp(self):
        super().setUp()
        self.user = make_user()
        token = str(RefreshToken.for_user(self.user).access_token)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
        ws = self.client.post(
            "/api/workspaces/",
            data={"name": "Cap Team", "encrypted_workspace_key": "enc-key"},
            content_type="application/json",
            **self.headers,
        )
        self.workspace_id = ws.json()["data"]["id"]

    def _create_project(self, name):
        return self.client.post(
            "/api/projects/",
            data={"name": name, "workspace_id": self.workspace_id},
            content_type="application/json",
            **self.headers,
        )

    def _put_secrets(self, project_id, keys):
        return self.client.post(
            "/api/secrets/",
            data={
                "project_id": project_id,
                "environment": "development",
                "secrets": {k: f"value-{k}" for k in keys},
            },
            content_type="application/json",
            **self.headers,
        )

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True, UNVERIFIED_PROJECT_LIMIT=1)
    def test_unverified_stops_at_the_project_cap(self):
        self.assertEqual(self._create_project("first").status_code, 201)
        resp = self._create_project("second")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["code"], "unverified_user")

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True, UNVERIFIED_SECRET_LIMIT=5)
    def test_unverified_stops_at_the_secret_cap_and_can_still_update(self):
        project_id = self._create_project("first").json()["data"]["id"]
        self.assertEqual(
            self._put_secrets(project_id, ["A", "B", "C", "D"]).status_code, 201
        )
        # One more fits under the cap of five.
        self.assertEqual(self._put_secrets(project_id, ["E"]).status_code, 201)
        # A sixth is refused.
        resp = self._put_secrets(project_id, ["F"])
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["code"], "unverified_user")
        # Overwriting what is already there is always allowed.
        self.assertEqual(self._put_secrets(project_id, ["A"]).status_code, 201)

    @override_settings(REQUIRE_EMAIL_VERIFICATION=True)
    def test_verified_account_passes_the_caps(self):
        self.user.is_email_verified = True
        self.user.save(update_fields=["is_email_verified"])
        project_id = self._create_project("first").json()["data"]["id"]
        self.assertEqual(self._create_project("second").status_code, 201)
        self.assertEqual(
            self._put_secrets(project_id, [f"K{i}" for i in range(8)]).status_code, 201
        )
