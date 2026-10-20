"""Filtered telemetry summary: the dashboard cards must describe the same rows
as the table, and the quota number must stay cloud-only."""

from datetime import timedelta

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

    def test_summary_carries_every_field_the_cards_read(self):
        # The web client reads these keys directly and falls back to 0 (or
        # null) when they are absent, so a missing key renders as a truthful
        # looking zero on the card. The response contract has to carry all of
        # them, otherwise the dashboard silently under-reports.
        data = self._summary()

        for field in (
            "ok",
            "blocked",
            "redacted",
            "cloud_requests",
            "cli_requests",
            "env_requests",
            "retention",
        ):
            self.assertIn(field, data)

    def _logs(self, query=""):
        res = self.client.get(
            f"/api/audit/logs/?workspace_id={self.workspace.id}{query}",
            **self.headers,
        )
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]

    def test_list_logs_offset_paging_serves_distinct_pages_in_order(self):
        # The web client's infinite scroll pages with limit+1/offset
        # (api-client.ts fetchRecentLogs). Each page must be disjoint and
        # ordered newest-first, or "Load more" repeats or skips rows.
        base = timezone.now()
        for i in range(5):
            AuditLogEntry.objects.create(
                workspace=self.workspace,
                timestamp=base - timedelta(minutes=i),
                target_domain=f"paged{i}.pagetest.example.com",
                method="GET",
                status_code=200,
                duration_ms=5,
                source="cloud",
                resolution_path="direct_resolve",
            )

        page1 = self._logs("&limit=2&offset=0&domain=pagetest.example.com")
        page2 = self._logs("&limit=2&offset=2&domain=pagetest.example.com")
        page3 = self._logs("&limit=2&offset=4&domain=pagetest.example.com")

        ids = [row["id"] for row in page1 + page2 + page3]
        self.assertEqual(len(ids), 5)
        self.assertEqual(len(set(ids)), 5)
        stamps = [row["timestamp"] for row in page1 + page2 + page3]
        self.assertEqual(stamps, sorted(stamps, reverse=True))

    def test_summary_honours_the_list_filters(self):
        cloud_only = self._summary("&source=cloud")
        self.assertEqual(cloud_only["totals"]["requests"], 2)
        self.assertEqual(cloud_only["cli_requests"], 0)

        # The cache key includes the filters; a filtered call after an
        # unfiltered one must not return the cached unfiltered totals.
        cli_only = self._summary("&source=cli")
        self.assertEqual(cli_only["totals"]["requests"], 1)
        self.assertEqual(cli_only["cloud_requests"], 0)


class AuditSummaryCardTableParityTests(TestCase):
    """The card must count exactly the rows the table shows, and the summary
    must never be staler than the list when new rows land."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.user = User.objects.create_user(
            email="parity_owner@example.com",
            password="SecurePassword123!",
            first_name="Parity",
            last_name="Owner",
        )
        self.workspace = Workspace.objects.create(name="Parity Workspace", owner=self.user)
        Membership.objects.create(
            workspace=self.workspace,
            user=self.user,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key="key",
        )
        refresh = RefreshToken.for_user(self.user)
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}"}

    def _summary(self, query=""):
        res = self.client.get(
            f"/api/audit/summary/?workspace_id={self.workspace.id}{query}",
            **self.headers,
        )
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]

    def _logs(self, query=""):
        res = self.client.get(
            f"/api/audit/logs/?workspace_id={self.workspace.id}{query}",
            **self.headers,
        )
        self.assertEqual(res.status_code, 200)
        return res.json()["data"]

    def _cloud_payload(self):
        return [{
            "workspace_id": str(self.workspace.id),
            "timestamp": timezone.now().isoformat(),
            "identity_level": "issued",
            "credential_ref": "k",
            "injection_style": "bearer",
            "target_domain": "api.stripe.com",
            "target_url": "https://api.stripe.com/v1/charges",
            "method": "POST",
            "status_code": 200,
            "duration_ms": 5,
            "resolution_path": "direct_resolve",
            "source": "cloud",
        }]

    def test_empty_source_row_agrees_between_table_and_card(self):
        # A row persisted with an empty source (a write that bypassed the
        # derivation guard) must not split: the table's Origin column reads it
        # as cloud, so the cloud bucket and the Origin=cloud filter must too.
        AuditLogEntry.objects.create(
            workspace=self.workspace,
            timestamp=timezone.now(),
            target_domain="api.stripe.com",
            method="GET",
            status_code=200,
            duration_ms=5,
            source="",
            resolution_path="direct_resolve",
        )

        logs = self._logs()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["source"], "cloud")

        data = self._summary()
        self.assertEqual(data["totals"]["requests"], 1)
        self.assertEqual(data["cloud_requests"], 1)

        filtered = self._summary("&source=cloud")
        self.assertEqual(filtered["totals"]["requests"], 1)
        self.assertEqual(len(self._logs("&source=cloud")), 1)

    def test_summary_refreshes_when_the_ingest_endpoint_adds_rows(self):
        # The summary caches for 60s while the list reads live. Without an
        # invalidation on write, a fresh list beside a cached card contradicts
        # the table for up to a minute — the user sees rows the card denies.
        self.assertEqual(self._summary()["totals"]["requests"], 0)

        res = self.client.post(
            "/api/internal/audit/logs/",
            data=self._cloud_payload(),
            content_type="application/json",
            **self.headers,
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["created_count"], 1)

        self.assertEqual(self._summary()["totals"]["requests"], 1)
        self.assertEqual(self._summary()["cloud_requests"], 1)