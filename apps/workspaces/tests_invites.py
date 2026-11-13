"""Invitations grant nothing until the invited address accepts.

The load-bearing properties: an unaccepted invitation creates no membership,
a token cannot be redeemed by a different address, the code locks after a few
guesses, and the workspace stays locked until an admin client seals its key.
"""
from unittest.mock import patch

from asgiref.sync import async_to_sync
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces import invites
from apps.workspaces.models import (
    InviteStatus,
    Membership,
    MembershipStatus,
    WorkspaceInvite,
)

SEND = "apps.common.email.brevo.send"


def make_user(email: str, verified: bool = True) -> User:
    user = User.objects.create_user(
        first_name="In", last_name="Vitee", email=email, password="password123"
    )
    user.is_email_verified = verified
    user.save(update_fields=["is_email_verified"])
    return user


class InviteTests(TestCase):
    def setUp(self):
        super().setUp()
        self.owner = make_user("owner@example.com")
        self.headers = self._auth(self.owner)
        resp = self.client.post(
            "/api/workspaces/",
            data={"name": "Invite Team", "encrypted_workspace_key": "owner-key"},
            content_type="application/json",
            **self.headers,
        )
        self.workspace_id = resp.json()["data"]["id"]
        self.send = patch(SEND, return_value=True)
        self.send.start()
        self.addCleanup(self.send.stop)

    def _auth(self, user):
        return {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(user).access_token}"
        }

    def _invite(self, email, role="member", key=""):
        return self.client.post(
            f"/api/workspaces/{self.workspace_id}/members/",
            data={
                "email": email,
                "role": role,
                "encrypted_workspace_key": key,
            },
            content_type="application/json",
            **self.headers,
        )

    def _accept(self, user, **body):
        return self.client.post(
            "/api/invites/accept/",
            data=body,
            content_type="application/json",
            **self._auth(user),
        )

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_invite_to_a_non_user_is_pending_and_grants_nothing(self, _code):
        resp = self._invite("outsider@example.com")
        self.assertEqual(resp.status_code, 201)

        invite = WorkspaceInvite.objects.get(email="outsider@example.com")
        self.assertEqual(invite.status, InviteStatus.PENDING)
        self.assertFalse(Membership.objects.filter(workspace_id=self.workspace_id).exclude(user=self.owner).exists())

        # The invitee's workspace list is still empty before acceptance.
        outsider = make_user("outsider@example.com")
        listed = self.client.get("/api/workspaces/", **self._auth(outsider))
        self.assertEqual(listed.json()["data"], [])

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_accept_by_code_creates_a_locked_membership_and_verifies(self, _code):
        self._invite("new@example.com")
        user = make_user("new@example.com", verified=False)

        resp = self._accept(user, code="123456")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["data"]
        self.assertEqual(data["workspace_id"], self.workspace_id)
        self.assertTrue(data["key_pending"])

        membership = Membership.objects.get(
            user=user, workspace_id=self.workspace_id
        )
        self.assertEqual(membership.status, MembershipStatus.ACTIVE)
        self.assertEqual(membership.encrypted_workspace_key, "")

        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        invite = WorkspaceInvite.objects.get(email="new@example.com")
        self.assertEqual(invite.status, InviteStatus.ACCEPTED)

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_a_different_address_cannot_redeem_the_token(self, _code):
        with patch(
            "apps.workspaces.invites.secrets.token_urlsafe", return_value="link-token"
        ):
            self._invite("intended@example.com")

        intruder = make_user("intruder@example.com")
        resp = self._accept(intruder, token="link-token")
        self.assertEqual(resp.status_code, 401)
        self.assertFalse(
            Membership.objects.filter(user=intruder, workspace_id=self.workspace_id).exists()
        )

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_a_wrong_code_locks_the_invite_after_the_attempt_cap(self, _code):
        self._invite("new@example.com")
        user = make_user("new@example.com")
        for _ in range(5):
            self.assertEqual(self._accept(user, code="000000").status_code, 401)
        resp = self._accept(user, code="123456")
        self.assertEqual(resp.status_code, 429)
        self.assertFalse(
            Membership.objects.filter(user=user, workspace_id=self.workspace_id).exists()
        )

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_an_expired_invite_is_refused(self, _code):
        self._invite("new@example.com")
        WorkspaceInvite.objects.filter(email="new@example.com").update(
            expires_at=timezone.now() - timezone.timedelta(minutes=1)
        )
        user = make_user("new@example.com")
        self.assertEqual(self._accept(user, code="123456").status_code, 401)

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_reinviting_revokes_the_previous_link(self, _code):
        with patch(
            "apps.workspaces.invites.secrets.token_urlsafe", return_value="first-token"
        ):
            self._invite("new@example.com")
        with patch(
            "apps.workspaces.invites.secrets.token_urlsafe", return_value="second-token"
        ):
            self._invite("new@example.com")

        self.assertEqual(
            WorkspaceInvite.objects.filter(email="new@example.com").count(), 2
        )
        self.assertEqual(
            WorkspaceInvite.objects.get(email="new@example.com", status=InviteStatus.REVOKED).token_hash
            != WorkspaceInvite.objects.get(email="new@example.com", status=InviteStatus.PENDING).token_hash,
            True,
        )
        user = make_user("new@example.com")
        self.assertEqual(self._accept(user, token="first-token").status_code, 401)
        self.assertEqual(self._accept(user, token="second-token").status_code, 200)

    @override_settings(DEBUG=False)
    def test_undelivered_invitation_grants_nothing(self):
        with patch(SEND, return_value=False):
            resp = self._invite("new@example.com")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("not configured", resp.json()["data"][0]["error"])
        self.assertFalse(
            WorkspaceInvite.objects.filter(email="new@example.com").exists()
        )

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_admin_seals_the_key_after_acceptance(self, _code):
        self._invite("new@example.com")
        user = make_user("new@example.com")
        self.assertEqual(self._accept(user, code="123456").status_code, 200)

        resp = self._invite("new@example.com", key="sealed-key")
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["data"][0]["error"], "")

        membership = Membership.objects.get(
            user=user, workspace_id=self.workspace_id
        )
        self.assertEqual(membership.encrypted_workspace_key, "sealed-key")
        self.assertEqual(
            WorkspaceInvite.objects.get(email="new@example.com").status,
            InviteStatus.ACTIVE,
        )

        # And now the workspace is real for the invitee.
        listed = self.client.get("/api/workspaces/", **self._auth(user)).json()["data"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["encrypted_workspace_key"], "sealed-key")

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_free_workspace_seat_cap_counts_pending_invitations(self, _code):
        # Owner holds one seat, so two invitations fill a free workspace.
        for i in range(2):
            resp = self._invite(f"person{i}@example.com")
            self.assertEqual(resp.json()["data"][0]["error"], "")

        resp = self._invite("person2@example.com")
        self.assertIn("3 members", resp.json()["data"][0]["error"])
        self.assertFalse(
            WorkspaceInvite.objects.filter(email="person2@example.com").exists()
        )

    @override_settings(DEBUG=True, REQUIRE_EMAIL_VERIFICATION=True)
    def test_an_unverified_admin_cannot_invite(self):
        unverified = make_user("unverified@example.com", verified=False)
        resp = self.client.post(
            "/api/workspaces/",
            data={"name": "Second Team", "encrypted_workspace_key": "k"},
            content_type="application/json",
            **self._auth(unverified),
        )
        ws_id = resp.json()["data"]["id"]
        resp = self.client.post(
            f"/api/workspaces/{ws_id}/members/",
            data={"email": "target@example.com"},
            content_type="application/json",
            **self._auth(unverified),
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["code"], "unverified_user")

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_pending_list_is_scoped_to_the_signed_in_address(self, _code):
        self._invite("new@example.com")
        user = make_user("new@example.com")
        other = make_user("other@example.com")

        mine = self.client.get("/api/invites/pending/", **self._auth(user))
        self.assertEqual(len(mine.json()["data"]), 1)
        self.assertEqual(mine.json()["data"][0]["workspace_name"], "Invite Team")

        theirs = self.client.get("/api/invites/pending/", **self._auth(other))
        self.assertEqual(theirs.json()["data"], [])

    @override_settings(DEBUG=True)
    @patch("apps.workspaces.invites._generate_code", return_value="123456")
    def test_preview_masks_the_address_and_needs_no_auth(self, _code):
        make_user("someone@example.com")
        with patch(
            "apps.workspaces.invites.secrets.token_urlsafe", return_value="preview-token"
        ):
            self._invite("someone@example.com")
        resp = self.client.get("/api/invites/preview/?token=preview-token")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["data"]
        self.assertEqual(data["workspace_name"], "Invite Team")
        self.assertEqual(data["email"], "s******@example.com")
        self.assertTrue(data["has_account"])
