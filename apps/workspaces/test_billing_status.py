"""The plan read the CLI uses to gate custom environments.

Creating a custom environment is a Pro privilege, so the client has to be able
to ask "is this workspace Pro" and get an answer the resolver agrees with. The
local ``tier`` mirror only moves on an explicit reconcile, so reading it alone
reports a fresh upgrade as Free. These tests pin the resolver-confirmed
direction, the trusted direction, and who may ask.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import (
    Membership,
    MembershipRole,
    MembershipStatus,
    Workspace,
    WorkspaceTier,
)

_OWNER_HEADERS = object()


class BillingStatusTestBase(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.owner = User.objects.create_user(
            email="billing_owner@example.com",
            password="SecurePassword123!",
            first_name="Owner",
            last_name="User",
        )
        self.workspace = Workspace.objects.create(name="Billing Status", owner=self.owner)
        Membership.objects.create(
            workspace=self.workspace,
            user=self.owner,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="owner_key",
        )
        self.member = User.objects.create_user(
            email="billing_member@example.com",
            password="SecurePassword123!",
            first_name="Member",
            last_name="User",
        )
        Membership.objects.create(
            workspace=self.workspace,
            user=self.member,
            role=MembershipRole.MEMBER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="member_key",
        )
        self.headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.owner).access_token}"
        }
        self.member_headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(self.member).access_token}"
        }

    def _status(self, headers=_OWNER_HEADERS):
        if headers is _OWNER_HEADERS:
            headers = self.headers
        return self.client.get(
            f"/api/workspaces/{self.workspace.id}/billing/status/",
            **headers,
        )

    def _tier(self, headers=_OWNER_HEADERS):
        res = self._status(headers)
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]["tier"]


class BillingStatusFreeMirrorTests(BillingStatusTestBase):
    """A Free mirror is the ambiguous direction, so it asks the resolver."""

    def test_active_resolver_plan_overrides_a_free_mirror(self):
        async def fake_plan(**_kwargs):
            return {"plan": "pro", "status": "active"}

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._tier(), "pro")

    def test_inactive_resolver_plan_stays_free(self):
        async def fake_plan(**_kwargs):
            return {"plan": "pro", "status": "past_due"}

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._tier(), "free")

    def test_unreachable_resolver_falls_back_to_the_mirror(self):
        async def fake_plan(**_kwargs):
            return None

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._tier(), "free")

    def test_an_upgraded_answer_is_cached(self):
        calls = []

        async def fake_plan(**_kwargs):
            calls.append(1)
            return {"plan": "pro", "status": "active"}

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._tier(), "pro")
            self.assertEqual(self._tier(), "pro")

        self.assertEqual(len(calls), 1)


class BillingStatusProMirrorTests(BillingStatusTestBase):
    """A Pro mirror is only ever set by a resolver-confirmed reconcile."""

    def test_pro_mirror_is_trusted_without_calling_the_resolver(self):
        Workspace.objects.filter(id=self.workspace.id).update(tier=WorkspaceTier.PRO)

        async def fail_if_called(**_kwargs):
            raise AssertionError("the resolver must not be asked when the mirror says Pro")

        with patch("apps.workspaces.selectors.resolver_plan", fail_if_called):
            self.assertEqual(self._tier(), "pro")


class BillingStatusAccessTests(BillingStatusTestBase):
    """Any member may ask; nobody else may."""

    def test_a_plain_member_can_read_the_plan(self):
        async def fake_plan(**_kwargs):
            return {"plan": "pro", "status": "active"}

        with patch("apps.workspaces.selectors.resolver_plan", fake_plan):
            self.assertEqual(self._tier(self.member_headers), "pro")

    def test_a_non_member_gets_404(self):
        outsider = User.objects.create_user(
            email="billing_outsider@example.com",
            password="SecurePassword123!",
            first_name="Out",
            last_name="Sider",
        )
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {RefreshToken.for_user(outsider).access_token}"
        }
        self.assertEqual(self._status(headers).status_code, 404)

    def test_an_anonymous_caller_gets_401(self):
        self.assertEqual(self._status({}).status_code, 401)
