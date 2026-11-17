# Standard library
from datetime import date
from unittest.mock import patch

# Django
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

# Local
from apps.accounts.models import User
from apps.telemetry.models import TelemetrySnapshot, DailyMetricsAggregate
from apps.workspaces.models import AuditLogEntry, ForensicAuditLogEntry, Workspace


class TelemetryEndpointTests(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.user = User.objects.create_user(
            email="test_telemetry@example.com",
            password="testpassword123",
            first_name="Test",
            last_name="Telemetry",
        )

    def test_sync_legacy_single(self):
        """Verify sync endpoint accepts a single snapshot dictionary."""
        payload = {
            "cli_version": "3.0.0",
            "os": "linux",
            "arch": "amd64",
            "command_executions": {"init": 1, "secrets": 5},
            "user_email": "test_telemetry@example.com",
        }
        response = self.client.post(
            "/telemetry/sync/",
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        self.assertEqual(TelemetrySnapshot.objects.count(), 1)

        snap = TelemetrySnapshot.objects.first()
        self.assertEqual(snap.cli_version, "3.0.0")
        self.assertEqual(snap.os, "linux")
        self.assertEqual(snap.command_executions, {"init": 1, "secrets": 5})

    def test_sync_snapshots_format(self):
        """Verify sync endpoint accepts {"snapshots": [...]} format."""
        payload = {
            "snapshots": [
                {
                    "cli_version": "3.0.1",
                    "os": "darwin",
                    "command_executions": {"proxy": 10},
                    "user_email": "test_telemetry@example.com",
                    "typos": None,
                }
            ]
        }
        response = self.client.post(
            "/telemetry/sync/",
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(TelemetrySnapshot.objects.count(), 1)
        snap = TelemetrySnapshot.objects.first()
        self.assertEqual(snap.cli_version, "3.0.1")
        self.assertEqual(snap.typos, {})

    def test_sync_daily_format(self):
        """Verify sync endpoint accepts {"daily": {"YYYY-MM-DD": {...}}} format."""
        payload = {
            "daily": {
                "2026-07-07": {
                    "cli_version": "3.0.2",
                    "os": "windows",
                    "command_executions": {"env": 3},
                }
            }
        }
        response = self.client.post(
            "/telemetry/sync/",
            data=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(TelemetrySnapshot.objects.count(), 1)
        snap = TelemetrySnapshot.objects.first()
        self.assertEqual(snap.cli_version, "3.0.2")
        self.assertEqual(snap.client_timestamp.date(), date(2026, 7, 7))

    def test_sync_rate_limiting_anon(self):
        """Verify anonymous requests are blocked after the 5th request."""
        payload = {"command_executions": {"init": 1}}
        for i in range(5):
            response = self.client.post(
                "/telemetry/sync/",
                data=payload,
                content_type="application/json",
                HTTP_X_FORWARDED_FOR="1.1.1.1",
            )
            self.assertEqual(response.status_code, 200, f"Req {i} failed")

        # 6th request should fail
        response = self.client.post(
            "/telemetry/sync/",
            data=payload,
            content_type="application/json",
            HTTP_X_FORWARDED_FOR="1.1.1.1",
        )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["code"], "rate_limited")

    def test_metrics_live_calculation(self):
        """Verify metrics endpoint calculates stats live when no aggregate exists."""
        # Create some snapshot data
        TelemetrySnapshot.objects.create(
            user=self.user,
            cli_version="3.0.0",
            os="linux",
            command_executions={"init": 2},
            proxy_calls=15,
            proxy_blocked=2,
            proxy_redacted=1,
            secrets_resolved=12,
        )

        response = self.client.get("/telemetry/metrics/")
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]

        self.assertEqual(data["platform"]["total_users"], 1)
        self.assertEqual(data["security"]["total_proxy_calls"], 15)
        self.assertEqual(data["security"]["total_proxy_blocked"], 2)
        self.assertEqual(data["security"]["total_proxy_redacted"], 1)
        self.assertEqual(data["security"]["total_secrets_resolved"], 12)
        self.assertEqual(data["security"]["breakdown"]["cli"]["proxy_calls"], 15)
        self.assertEqual(data["security"]["breakdown"]["cloud"]["resolver_calls"], 0)
        self.assertEqual(data["agent_infrastructure"]["execution_paths"]["cloud_resolver"], 0)

    def test_metrics_aggregate_breakdown(self):
        """Verify metrics endpoint correctly pulls CLI/Cloud breakdown from aggregate."""
        DailyMetricsAggregate.objects.create(
            date=timezone.now().date(),
            total_users=10,
            total_proxy_calls=150,
            total_proxy_calls_cli=100,
            total_proxy_calls_cloud=50,
            total_proxy_blocked=5,
            total_proxy_redacted=2,
            total_secrets_resolved=120,
            command_usage={"exec": 50},
            integration_usage={"env": 5},
            environment_distribution={"production": 10},
        )

        response = self.client.get("/telemetry/metrics/")
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]

        self.assertEqual(data["security"]["total_proxy_calls"], 150)
        self.assertEqual(data["security"]["breakdown"]["cli"]["proxy_calls"], 100)
        self.assertEqual(data["security"]["breakdown"]["cloud"]["resolver_calls"], 50)
        self.assertEqual(data["agent_infrastructure"]["execution_paths"]["cloud_resolver"], 50)

    def test_metrics_cache_hit(self):
        """Verify metrics endpoint returns cached data directly if present."""
        cached_report = {"cached": True, "platform": {"total_users": 100}}
        cache.set("public_platform_metrics", cached_report, 3600)

        response = self.client.get("/telemetry/metrics/")
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertTrue(data["cached"])
        self.assertEqual(data["platform"]["total_users"], 100)

    @patch("apps.telemetry.services.call_command")
    def test_compute_metrics_cron_auth_and_trigger(self, mock_call_command):
        """Verify cron endpoint triggers metrics calculation with valid secret."""
        # 1. Unauthenticated request
        response = self.client.get("/telemetry/internal/compute-metrics/")
        self.assertEqual(response.status_code, 401)
        mock_call_command.assert_not_called()

        # 2. Authenticated request with valid secret
        with self.settings(CRON_SECRET="valid-cron-token"):
            response = self.client.get(
                "/telemetry/internal/compute-metrics/",
                HTTP_AUTHORIZATION="Bearer valid-cron-token",
            )
            self.assertEqual(response.status_code, 200)
            mock_call_command.assert_called_once_with("calculate_metrics")

    def test_command_classification_and_alias_usage(self):
        """Verify server, login, logout, and alias_usage classification and endpoint presentation."""
        from apps.telemetry.commands import process_command_executions

        raw_commands = {
            "login": 10,
            "logout": 2,
            "server": 5,
            "list-secrets": 8,
            "pull-secrets": 3,
            "create-project": 4,
            "secrets": 20,
            "bad_cmd": 1,
        }

        canonical, hierarchical, typos, aliases = process_command_executions(raw_commands)

        # 1. Verify domains
        self.assertIn("login", canonical)
        self.assertEqual(canonical["login"], 10)
        self.assertIn("logout", canonical)
        self.assertEqual(canonical["logout"], 2)
        self.assertIn("server", canonical)
        self.assertEqual(canonical["server"], 5)
        self.assertNotIn("auth", canonical)

        # 2. Verify server is NOT in typos
        self.assertNotIn("server", typos)
        self.assertIn("bad_cmd", typos)

        # 3. Verify aliases are tracked
        self.assertEqual(aliases.get("list-secrets"), 8)
        self.assertEqual(aliases.get("pull-secrets"), 3)
        self.assertEqual(aliases.get("create-project"), 4)
        self.assertNotIn("secrets", aliases)

        # 4. Verify endpoint includes alias_usage
        DailyMetricsAggregate.objects.create(
            date=timezone.now().date(),
            total_users=10,
            total_proxy_calls=10,
            command_usage=canonical,
            alias_usage=aliases,
            typos_usage=typos,
            integration_usage={"env": 2},
            environment_distribution={"development": 10},
        )

        response = self.client.get("/telemetry/metrics/")
        self.assertEqual(response.status_code, 200)
        fa = response.json()["data"]["feature_adoption"]
        self.assertIn("alias_usage", fa)
        self.assertEqual(fa["alias_usage"]["list-secrets"], 8)
        self.assertEqual(fa["command_usage"]["server"], 5)
        self.assertNotIn("server", fa["typos_usage"])


class CommandPathClassificationTests(TestCase):
    """One action must land in one bucket, whether it is reached through the
    canonical noun-then-action tree or through a verb-noun shortcut."""

    def test_path_and_shortcut_resolve_identically(self):
        from apps.telemetry.commands import classify_command

        cases = [
            ("secrets pull", ("secrets", "pull")),
            ("pull-secrets", ("secrets", "pull")),
            ("agent token issue worker", ("agents", "issue_token")),
            ("workspace allowlist add example.com", ("workspaces", "allowlist_add")),
            ("workspace allowlist logs", ("workspaces", "allowlist_logs")),
            ("environment copy", ("environment", "copy")),
            ("proxy rotate-session", ("proxy", "rotate_session")),
            ("mcp bridge", ("mcp", "bridge")),
            ("server set https://api.example.com", ("server", "set")),
            ("logs replay abc123", ("logs", "replay")),
            # A trailing argument is not a subcommand and never a typo.
            ("call POST", ("call", "general")),
            ("secrets set STRIPE_KEY", ("secrets", "set")),
        ]
        for raw, want in cases:
            with self.subTest(raw=raw):
                domain, action, is_typo = classify_command(raw)
                self.assertEqual((domain, action), want)
                self.assertFalse(is_typo)

    def test_unknown_head_is_typo_keyed_by_head_only(self):
        from apps.telemetry.commands import classify_command

        self.assertEqual(classify_command("bogus sub"), ("typos", "bogus", True))
        self.assertEqual(classify_command("statut"), ("typos", "statut", True))

    def test_aggregation_merges_paths_and_keeps_alias_table_clean(self):
        from apps.telemetry.commands import process_command_executions

        canonical, hierarchical, typos, aliases = process_command_executions(
            {"secrets pull": 4, "pull-secrets": 2, "agent token issue": 3, "bogus": 1}
        )

        self.assertEqual(canonical["secrets"], 6)
        self.assertEqual(canonical["agents"], 3)
        self.assertEqual(hierarchical["secrets"]["actions"]["pull"], 6)
        self.assertEqual(hierarchical["agents"]["actions"]["issue_token"], 3)
        self.assertEqual(typos["bogus"], 1)
        # Canonical paths are usage, not shortcut aliases.
        self.assertEqual(aliases.get("pull-secrets"), 2)
        self.assertNotIn("secrets pull", aliases)


class CloudResolutionStatsTests(TestCase):
    """Cloud counters come from the forensic twin, which records the real
    decision and the number of secret handles in scope."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.user = User.objects.create_user(
            email="metrics_cloud@example.com",
            password="testpassword123",
            first_name="Metrics",
            last_name="Cloud",
        )
        self.workspace = Workspace.objects.create(name="Metrics Workspace", owner=self.user)

    def _forensic(self, decision, secrets_count=0, redaction_triggered=False):
        from uuid import uuid4

        return ForensicAuditLogEntry.objects.create(
            workspace=self.workspace,
            correlation_id=f"corr_{uuid4().hex[:12]}",
            enforcement_json={"decision": decision},
            snapshot_json={"secrets_count": secrets_count},
            resolution_json={"redaction_triggered": redaction_triggered},
        )

    def _audit(self, *, duration_ms=10, redacted=False):
        return AuditLogEntry.objects.create(
            workspace=self.workspace,
            timestamp=timezone.now(),
            credential_ref="",
            injection_style="bearer",
            target_domain="api.example.com",
            target_url="https://api.example.com/v1",
            target_path="/v1",
            method="POST",
            status_code=200,
            duration_ms=duration_ms,
            redacted=redacted,
            resolution_path="direct_resolve",
            caller_role="agent",
        )

    def test_blocked_calls_are_not_counted_as_redactions(self):
        from apps.telemetry.aggregations import cloud_resolution_stats

        self._forensic("permitted", secrets_count=2)
        self._forensic("permitted", secrets_count=3)
        self._forensic("permitted", secrets_count=1, redaction_triggered=True)
        # A blocked call is written to the audit trail with redacted=True; it
        # must count as a block, never as a redaction or a resolved secret.
        self._forensic("blocked", secrets_count=0)

        stats = cloud_resolution_stats()
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["redacted"], 1)
        self.assertEqual(stats["secrets_resolved"], 6)

    def test_call_stats_use_the_resolver_duration_column(self):
        from apps.telemetry.aggregations import cloud_call_stats

        self._audit(duration_ms=10)
        self._audit(duration_ms=32)

        self.assertEqual(cloud_call_stats(), {"calls": 2, "duration_ms": 42})
