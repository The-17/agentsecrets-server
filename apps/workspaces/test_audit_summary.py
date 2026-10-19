"""Filtered telemetry summary: the dashboard cards must describe the same rows
as the table, and the quota number must stay cloud-only."""

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.workspaces.models import AuditLogEntry, Membership, MembershipRole, MembershipStatus, Workspace


class AuditSummaryFilterTests(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.user = User.objects.create_user(
            email="summary_owner@example.com",
            password="SecurePassword123!",
            first_name="Summary",
            last_name="Owner",
        )
        self.workspace = Workspace.objects.create(name="Summary Workspace", owner=self.user)
        Membership.objects.create(
            workspace=self.workspace,
            user=self.user,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="key",
        )
        refresh = RefreshToken.for_user(self.user)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}

        AuditLogEntry.objects.create(
            workspace=self.workspace,
            timestamp=timezone.now(),
            target_domain="api.stripe.com",
            method="POST",
            status_code=200,
            duration_ms=10,
            source="cloud",
            resolution_path="direct_resolve",
        )
        AuditLogEntry.objects.create(
            workspace=self.workspace,
            timestamp=timezone.now(),
            target_domain="api.openai.com",
            method="GET",
            status_code=200,
            duration_ms=8,
            source="cli",
            resolution_path="local proxy",
            redacted=True,
        )
        AuditLogEntry.objects.create(
            workspace=self.workspace,
            timestamp=timezone.now(),
            target_domain="blocked.example.com",
            method="POST",
            status_code=403,
            duration_ms=4,
            source="cloud",
            resolution_path="direct_resolve",
        )

    def _summary(self, query=""):
        res = self.client.get(
            f"/api/audit/summary/?workspace_id={self.workspace.id}{query}",
            **self.headers,
        )
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]

    def test_counts_split_ok_blocked_redacted_and_source(self):
        data = self._summary()

        self.assertEqual(data["totals"]["requests"], 3)
        self.assertEqual(data["ok"], 2)
        self.assertEqual(data["blocked"], 1)
        self.assertEqual(data["redacted"], 1)
        # Quota is cloud only. Local CLI rows are not part of it.
        self.assertEqual(data["cloud_requests"], 2)
        self.assertEqual(data["cli_requests"], 1)

    def test_summary_honours_the_list_filters(self):
        cloud_only = self._summary("&source=cloud")
        self.assertEqual(cloud_only["totals"]["requests"], 2)
        self.assertEqual(cloud_only["cli_requests"], 0)

        # The cache key includes the filters; a filtered call after an
        # unfiltered one must not return the cached unfiltered totals.
        cli_only = self._summary("&source=cli")
        self.assertEqual(cli_only["totals"]["requests"], 1)
        self.assertEqual(cli_only["cloud_requests"], 0)