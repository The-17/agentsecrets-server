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
