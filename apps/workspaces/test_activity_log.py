"""Tier-1 workspace activity: plan retention and action coverage.

Retention is a billing promise (Free 3 days, Pro 30), so it is enforced
server-side on this stream too, not only on the telemetry stream. Coverage
tests pin the managerial actions that the dashboard filters expose: a filter
over an action nobody records is an empty promise.
"""

from datetime import timedelta

from asgiref.sync import async_to_sync
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Workspace,
    WorkspaceActivityLog,
    WorkspaceTier,
)


class ActivityTestBase(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.owner = User.objects.create_user(
            email="activity_owner@example.com",
            password="SecurePassword123!",
            first_name="Owner",
            last_name="User",
        )
        self.workspace = Workspace.objects.create(name="Activity Workspace", owner=self.owner)
        Membership.objects.create(
            workspace=self.workspace,
            user=self.owner,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="owner_key",
        )
        refresh = RefreshToken.for_user(self.owner)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}

    def _row(self, action, days_ago, target_type="secret", target_name="STRIPE_KEY"):
        row = WorkspaceActivityLog.objects.create(
            workspace=self.workspace,
            action=action,
            target_type=target_type,
            target_name=target_name,
            actor=self.owner,
            actor_email=self.owner.email,
        )
        # created_at is auto_now_add; force the age through an UPDATE.
        WorkspaceActivityLog.objects.filter(id=row.id).update(
            created_at=timezone.now() - timedelta(days=days_ago)
        )
        return row


class ActivityRetentionTests(ActivityTestBase):
    """The activity stream obeys the same plan window as the telemetry stream."""

    def _fetch(self):
        res = self.client.get(
            f"/api/workspaces/{self.workspace.id}/activity/", **self.headers
        )
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]

    def test_free_plan_clamps_activity_to_three_days(self):
        self._row("secret.created", days_ago=1)
        self._row("secret.created", days_ago=10)

        rows = self._fetch()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "secret.created")

    def test_pro_plan_keeps_thirty_days_of_activity(self):
        self.workspace.tier = WorkspaceTier.PRO
        self.workspace.save(update_fields=["tier"])
        self._row("secret.created", days_ago=1)
        self._row("secret.created", days_ago=10)

        self.assertEqual(len(self._fetch()), 2)

    def test_workspace_without_payable_billing_id_is_free(self):
        """A workspace with no payable account falls back to the Free window."""
        from apps.workspaces.selectors import AuditSelector

        days, restricted = async_to_sync(AuditSelector.retention_window)(
            workspace_id=str(self.workspace.id)
        )

        self.assertEqual((days, restricted), (3, True))


class ResolverTierTests(ActivityTestBase):
    """The retention gate confirms a Free mirror with the resolver."""

    def _window(self):
        from apps.workspaces.selectors import AuditSelector

        return async_to_sync(AuditSelector.retention_window)(
            workspace_id=str(self.workspace.id)
        )

    def test_active_pro_plan_overrides_a_free_mirror(self):
        from unittest.mock import patch

        async def fake_plan(**_kwargs):
            return {"plan": "pro", "status": "active"}

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._window(), (30, False))

    def test_inactive_pro_plan_stays_free(self):
        from unittest.mock import patch

        async def fake_plan(**_kwargs):
            return {"plan": "pro", "status": "past_due"}

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._window(), (3, True))


class ActivityFilterTests(ActivityTestBase):
    """Category and free-text filters run server-side over the whole stream."""

    def _seed(self):
        self._row("secret.created", days_ago=0, target_type="secret", target_name="STRIPE_KEY")
        self._row(
            "secret.rotation_promoted",
            days_ago=0,
            target_type="secret",
            target_name="OPENAI_KEY",
        )
        WorkspaceActivityLog.objects.create(
            workspace=self.workspace,
            action="allowlist.added",
            target_type="allowlist",
            target_name="api.stripe.com",
            actor=self.owner,
            actor_email=self.owner.email,
        )

    def _fetch(self, query=""):
        res = self.client.get(
            f"/api/workspaces/{self.workspace.id}/activity/{query}", **self.headers
        )
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]

    def test_category_separates_rotation_from_other_secret_actions(self):
        self._seed()

        rotation = self._fetch("?category=rotation")
        self.assertEqual([r["action"] for r in rotation], ["secret.rotation_promoted"])

        secrets_only = self._fetch("?category=secret")
        self.assertEqual([r["action"] for r in secrets_only], ["secret.created"])

    def test_category_member_and_allowlist(self):
        self._seed()
        self.assertEqual(
            [r["action"] for r in self._fetch("?category=allowlist")],
            ["allowlist.added"],
        )
        self.assertEqual(self._fetch("?category=member"), [])

    def test_search_matches_target_and_actor(self):
        self._seed()

        by_target = self._fetch("?q=api.stripe")
        self.assertEqual([r["target_name"] for r in by_target], ["api.stripe.com"])

        by_actor = self._fetch("?q=activity_owner")
        self.assertEqual(len(by_actor), 3)


class ActivityCoverageTests(ActivityTestBase):
    """Every managerial action the dashboard filters by must be recorded."""

    def test_allowlist_add_and_remove_are_recorded(self):
        res = self.client.post(
            f"/api/workspaces/{self.workspace.id}/allowlist/",
            data={"domains": ["api.stripe.com"]},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertTrue(
            WorkspaceActivityLog.objects.filter(
                action="allowlist.added", target_name="api.stripe.com"
            ).exists()
        )

        res = self.client.delete(
            f"/api/workspaces/{self.workspace.id}/allowlist/api.stripe.com/",
            **self.headers,
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(
            WorkspaceActivityLog.objects.filter(
                action="allowlist.removed", target_name="api.stripe.com"
            ).exists()
        )

    def test_member_invite_and_removal_are_recorded(self):
        invitee = User.objects.create_user(
            email="activity_invitee@example.com",
            password="SecurePassword123!",
            first_name="Invitee",
            last_name="User",
        )

        res = self.client.post(
            f"/api/workspaces/{self.workspace.id}/members/",
            data={
                "invites": [
                    {
                        "email": invitee.email,
                        "role": "member",
                        "encrypted_workspace_key": "invitee_key",
                    }
                ]
            },
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(res.status_code, 201)
        invited = WorkspaceActivityLog.objects.filter(action="member.invited").first()
        self.assertIsNotNone(invited)
        self.assertEqual(invited.target_name, invitee.email)
        self.assertEqual(invited.target_type, "member")

        membership = Membership.objects.get(workspace=self.workspace, user=invitee)
        res = self.client.delete(
            f"/api/workspaces/{self.workspace.id}/members/{membership.id}/",
            **self.headers,
        )
        self.assertIn(res.status_code, (200, 204))
        removed = WorkspaceActivityLog.objects.filter(action="member.removed").first()
        self.assertIsNotNone(removed)
        self.assertEqual(removed.target_name, invitee.email)

    def test_role_change_is_recorded(self):
        invitee = User.objects.create_user(
            email="activity_role@example.com",
            password="SecurePassword123!",
            first_name="Role",
            last_name="User",
        )
        membership = Membership.objects.create(
            workspace=self.workspace,
            user=invitee,
            role=MembershipRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="role_key",
        )

        res = self.client.patch(
            f"/api/workspaces/{self.workspace.id}/members/{membership.id}/",
            data={"role": "admin"},
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(res.status_code, 200)

        row = WorkspaceActivityLog.objects.filter(action="member.role_changed").first()
        self.assertIsNotNone(row)
        self.assertEqual(row.metadata.get("to"), MembershipRole.ADMIN)
        self.assertEqual(row.target_name, invitee.email)