import asyncio
import logging
from datetime import timedelta
from typing import Dict, Any, Optional, Set
from collections import Counter

from django.core.cache import cache
from django.db.models import Count, Sum, Avg, Q
from django.utils import timezone
from asgiref.sync import sync_to_async

from apps.accounts.models import User
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipStatus,
    AgentRegistration,
)
from .models import TelemetrySnapshot, DailyMetricsAggregate
from .commands import process_command_executions

logger = logging.getLogger("apps.telemetry")


class TelemetrySelector:
    """
    Query selector for telemetry snapshots, platform statistics, and aggregated metrics.
    """

    CACHE_KEY = "public_platform_metrics"

    @classmethod
    async def get_cached_metrics(cls) -> Optional[Dict[str, Any]]:
        return await sync_to_async(cache.get)(cls.CACHE_KEY)

    @classmethod
    async def set_cached_metrics(cls, data: Dict[str, Any], timeout: int = 300) -> None:
        await sync_to_async(cache.set)(cls.CACHE_KEY, data, timeout)

    @classmethod
    async def get_live_platform_state(cls) -> Dict[str, Any]:
        secret_policies, agent_policies = await asyncio.gather(
            Secret.objects.exclude(policy__isnull=True).exclude(policy__exact={}).acount(),
            AgentRegistration.objects.exclude(capabilities__isnull=True).exclude(capabilities__exact={}).acount(),
        )
        return {
            "total_users": await User.objects.acount(),
            "total_projects": await Project.objects.acount(),
            "total_secrets": await Secret.objects.acount(),
            "total_workspaces": await Workspace.objects.acount(),
            "shared_workspaces": await Workspace.objects.filter(type=WorkspaceType.SHARED).acount(),
            "team_workspaces": await Workspace.objects.filter(
                type=WorkspaceType.SHARED
            ).annotate(
                active_members=Count("memberships", filter=Q(memberships__status=MembershipStatus.ACTIVE))
            ).filter(active_members__gt=1).acount(),
            "pending_invites": await Membership.objects.filter(status=MembershipStatus.INVITED).acount(),
            "total_agents": await AgentRegistration.objects.acount(),
            "total_policies": secret_policies + agent_policies,
        }

    @classmethod
    async def get_live_env_distribution(cls) -> Dict[str, int]:
        return {
            "development": await Secret.objects.filter(environment="development").acount(),
            "staging": await Secret.objects.filter(environment="staging").acount(),
            "production": await Secret.objects.filter(environment="production").acount(),
        }

    @classmethod
    async def get_live_os_distribution(cls) -> Dict[str, str]:
        qs = (
            TelemetrySnapshot.objects.values("os")
            .annotate(unique_users=Count("user", distinct=True))
            .order_by("-unique_users")
        )
        results = {}
        total = 0
        async for item in qs:
            os_name = item["os"] or "unknown"
            count = item["unique_users"]
            results[os_name] = count
            total += count

        if total > 0:
            return {os_name: f"{round((count / total) * 100, 2)}%" for os_name, count in results.items()}
        return {}

    @classmethod
    async def get_today_live_metrics(cls, today) -> Dict[str, int]:
        now = timezone.now()
        rolling_daily = now - timedelta(hours=24)
        rolling_weekly = now - timedelta(days=7)
        rolling_monthly = now - timedelta(days=30)

        (
            active_counts,
            snap_users_today,
            new_signups,
            new_projects,
            new_secrets,
        ) = await asyncio.gather(
            User.objects.aaggregate(
                active_daily=Count("id", filter=Q(last_active_at__gte=rolling_daily)),
                active_weekly=Count("id", filter=Q(last_active_at__gte=rolling_weekly)),
                active_monthly=Count("id", filter=Q(last_active_at__gte=rolling_monthly)),
            ),
            TelemetrySnapshot.objects.filter(
                client_timestamp__date=today, user__isnull=False
            ).values("user").distinct().acount(),
            User.objects.filter(created_at__date=today).acount(),
            Project.objects.filter(created_at__date=today).acount(),
            Secret.objects.filter(created_at__date=today).acount(),
        )

        dau = max(active_counts["active_daily"], snap_users_today)
        return {
            "active_users_daily": dau,
            "active_users_weekly": active_counts["active_weekly"],
            "active_users_monthly": active_counts["active_monthly"],
            "new_signups_today": new_signups,
            "new_projects_today": new_projects,
            "new_secrets_today": new_secrets,
        }

    @classmethod
    async def get_platform_metrics_report(cls, bypass_cache: bool = False) -> Dict[str, Any]:
        if not bypass_cache:
            cached = await cls.get_cached_metrics()
            if cached:
                return cached

        today = timezone.now().date()
        yesterday_date = today - timedelta(days=1)
        week_ago_date = today - timedelta(days=7)
        month_ago_date = today - timedelta(days=30)

        (
            platform_state,
            env_dist,
            today_metrics,
            latest,
            agg_yesterday,
            agg_week_ago,
            agg_month_ago,
            os_dist,
            users_in_shared_workspaces,
        ) = await asyncio.gather(
            cls.get_live_platform_state(),
            cls.get_live_env_distribution(),
            cls.get_today_live_metrics(today),
            DailyMetricsAggregate.objects.order_by("-date").afirst(),
            DailyMetricsAggregate.objects.filter(date__lte=yesterday_date).order_by("-date").afirst(),
            DailyMetricsAggregate.objects.filter(date__lte=week_ago_date).order_by("-date").afirst(),
            DailyMetricsAggregate.objects.filter(date__lte=month_ago_date).order_by("-date").afirst(),
            cls.get_live_os_distribution(),
            Membership.objects.filter(
                workspace__type=WorkspaceType.SHARED, status=MembershipStatus.ACTIVE
            ).values("user").distinct().acount(),
        )

        if latest:
            dau = today_metrics["active_users_daily"]
            mau = today_metrics["active_users_monthly"]
            stickiness = f"{round((dau / mau) * 100, 2)}%" if mau > 0 else "0.00%"

            # Collaboration rates
            shared_ws = platform_state["shared_workspaces"]
            team_ws = platform_state["team_workspaces"]
            team_collab_rate = (
                f"{round((team_ws / shared_ws) * 100, 2)}%"
                if shared_ws > 0
                else "0.00%"
            )

            total_users = platform_state["total_users"]
            user_collab_rate = (
                f"{round((users_in_shared_workspaces / total_users) * 100, 2)}%"
                if total_users > 0
                else "0.00%"
            )

            total_secrets = platform_state["total_secrets"]
            prod_adoption = (
                f"{round((env_dist.get('production', 0) / total_secrets) * 100, 2)}%"
                if total_secrets > 0
                else "0.00%"
            )

            total_calls = latest.total_proxy_calls
            security_redaction = (
                f"{round((latest.total_proxy_redacted / total_calls) * 100, 2)}%"
                if total_calls > 0
                else "0.00%"
            )
            security_block = (
                f"{round((latest.total_proxy_blocked / total_calls) * 100, 2)}%"
                if total_calls > 0
                else "0.00%"
            )

            # Unique user adoption percentages
            integration_adoption = {}
            for integration, count in latest.integration_usage.items():
                pct = round((count / total_users) * 100, 2) if total_users > 0 else 0.0
                integration_adoption[integration] = f"{pct}%"

            command_usage = latest.command_usage
            total_cmds = sum(command_usage.values())
            command_share = {}
            for cmd, count in command_usage.items():
                pct = round((count / total_cmds) * 100, 2) if total_cmds > 0 else 0.0
                command_share[cmd] = f"{pct}%"

            # Growth helper with proper zero-baseline handling
            def _growth(curr, past_agg, field):
                if not past_agg:
                    return "0.00%"
                past_val = getattr(past_agg, field, 0)
                if past_val == 0:
                    return "+100.00%" if curr > 0 else "0.00%"
                pct = round(((curr - past_val) / past_val) * 100, 2)
                prefix = "+" if pct > 0 else ""
                return f"{prefix}{pct}%"

            analytics = {
                "stickiness_ratio_dau_mau": stickiness,
                "team_collaboration_index": team_collab_rate,
                "user_collaboration_rate": user_collab_rate,
                "production_adoption_rate": prod_adoption,
                "security_metrics": {
                    "redaction_rate": security_redaction,
                    "block_rate": security_block,
                },
                "user_growth": {
                    "dod": _growth(platform_state["total_users"], agg_yesterday, "total_users"),
                    "wow": _growth(platform_state["total_users"], agg_week_ago, "total_users"),
                    "mom": _growth(platform_state["total_users"], agg_month_ago, "total_users"),
                },
                "project_growth": {
                    "dod": _growth(platform_state["total_projects"], agg_yesterday, "total_projects"),
                    "wow": _growth(platform_state["total_projects"], agg_week_ago, "total_projects"),
                    "mom": _growth(platform_state["total_projects"], agg_month_ago, "total_projects"),
                },
                "secret_growth": {
                    "dod": _growth(platform_state["total_secrets"], agg_yesterday, "total_secrets"),
                    "wow": _growth(platform_state["total_secrets"], agg_week_ago, "total_secrets"),
                    "mom": _growth(platform_state["total_secrets"], agg_month_ago, "total_secrets"),
                },
                "dau_growth": {
                    "dod": _growth(dau, agg_yesterday, "active_users_daily"),
                    "wow": _growth(dau, agg_week_ago, "active_users_daily"),
                    "mom": _growth(dau, agg_month_ago, "active_users_daily"),
                },
                "integration_adoption": integration_adoption,
                "command_market_share": command_share,
                "cli_os_distribution": os_dist,
                "unique_agents": platform_state.get("total_agents", 0),
            }
            data = cls._build_from_aggregate(
                latest, platform_state, env_dist, today_metrics, today, analytics
            )
        else:
            data = await cls._build_live(platform_state, env_dist, os_dist, users_in_shared_workspaces)

        await cls.set_cached_metrics(data, timeout=300)
        return data

    @classmethod
    def _build_from_aggregate(
        cls, agg, platform_state, env_dist, today_metrics, today, analytics
    ) -> Dict[str, Any]:
        return {
            "platform": platform_state,
            "engagement": {
                "active_users_daily": today_metrics["active_users_daily"],
                "active_users_weekly": today_metrics["active_users_weekly"],
                "active_users_monthly": today_metrics["active_users_monthly"],
                "avg_secrets_per_project": agg.avg_secrets_per_project,
                "avg_projects_per_workspace": agg.avg_projects_per_workspace,
                "avg_members_per_shared_workspace": agg.avg_members_per_workspace,
            },
            "growth": {
                "new_signups_today": today_metrics["new_signups_today"],
                "new_projects_today": today_metrics["new_projects_today"],
                "new_secrets_today": today_metrics["new_secrets_today"],
            },
            "analytics": analytics,
            "security": {
                "total_proxy_calls": agg.total_proxy_calls,
                "total_proxy_blocked": agg.total_proxy_blocked,
                "total_proxy_redacted": agg.total_proxy_redacted,
                "total_secrets_resolved": agg.total_secrets_resolved,
                "breakdown": {
                    "cli": {
                        "proxy_calls": agg.integration_usage.get("cli_proxy", 0) if isinstance(agg.integration_usage, dict) else 0,
                    },
                    "cloud": {
                        "resolver_calls": agg.integration_usage.get("cloud_proxy", 0) if isinstance(agg.integration_usage, dict) else 0,
                    },
                },
            },
            "agent_infrastructure": {
                "execution_paths": {
                    "daemon": agg.total_proxy_calls_daemon,
                    "transient": agg.total_proxy_calls_transient,
                    "mcp": agg.total_proxy_calls_mcp,
                    "direct": agg.total_proxy_calls_direct,
                    "developer": agg.total_developer_commands,
                    "cloud_resolver": agg.integration_usage.get("cloud_proxy", 0) if isinstance(agg.integration_usage, dict) else 0,
                },
                "identity_levels": {
                    "anonymous": agg.total_identity_anonymous_calls,
                    "declared": agg.total_identity_declared_calls,
                    "issued": agg.total_identity_issued_calls,
                },
                "shielding": {
                    "ssrf_blocked": agg.total_ssrf_blocked,
                    "allowlist_violations": agg.total_allowlist_violations,
                    "capability_violations": agg.total_capability_violations_blocked,
                    "process_verifications_failed": agg.total_process_verifications_failed,
                    "process_verifications_passed": agg.total_process_verifications_passed,
                    "production_write_challenges": agg.total_production_write_challenges,
                },
            },
            "performance": {
                "avg_keychain_resolution_ms": agg.avg_keychain_resolution_ms,
                "avg_session_refresh_ms": agg.avg_session_refresh_ms,
                "total_proxy_duration_ms": agg.total_proxy_duration_ms,
            },
            "integrity": {
                "log_chain_verifications": agg.total_log_verifications,
                "tampering_alerts": agg.total_tampering_alerts,
                "active_keychains": agg.total_active_keychains,
                "headless_nodes": agg.total_headless_nodes,
            },
            "friction": {
                "interactive_prompts_shown": agg.total_interactive_prompts_shown,
                "interactive_prompts_skipped": agg.total_interactive_prompts_skipped,
                "drift_diffs_detected": agg.total_drift_diffs_detected,
            },
            "errors": {
                "auth": agg.total_errors_auth,
                "keychain": agg.total_errors_keychain,
                "secrets": agg.total_errors_secrets,
                "network": agg.total_errors_network,
                "system": agg.total_errors_system,
                "unknown": agg.total_errors_unknown,
            },
            "feature_adoption": {
                "environment_distribution": env_dist,
                "command_usage": agg.command_usage,
                "integration_usage": agg.integration_usage,
                "typos_usage": agg.typos_usage,
            },
            "report_date": str(today),
            "computed_at": timezone.now().isoformat(),
        }

    @classmethod
    async def _build_live(
        cls, platform_state, env_dist, os_dist, users_in_shared_workspaces: int
    ) -> Dict[str, Any]:
        now = timezone.now()
        today = now.date()
        rolling_daily = now - timedelta(hours=24)
        rolling_weekly = now - timedelta(days=7)
        rolling_monthly = now - timedelta(days=30)

        (
            active_counts,
            projects_with_secrets,
            active_shared_memberships,
            new_signups,
            new_projects,
            new_secrets,
            proxy_agg,
        ) = await asyncio.gather(
            User.objects.aaggregate(
                active_daily=Count("id", filter=Q(last_active_at__gte=rolling_daily)),
                active_weekly=Count("id", filter=Q(last_active_at__gte=rolling_weekly)),
                active_monthly=Count("id", filter=Q(last_active_at__gte=rolling_monthly)),
            ),
            Project.objects.filter(secrets__isnull=False).distinct().acount(),
            Membership.objects.filter(
                workspace__type=WorkspaceType.SHARED, status=MembershipStatus.ACTIVE
            ).acount(),
            User.objects.filter(created_at__date=today).acount(),
            Project.objects.filter(created_at__date=today).acount(),
            Secret.objects.filter(created_at__date=today).acount(),
            TelemetrySnapshot.objects.aaggregate(
                total_calls=Sum("proxy_calls"),
                total_blocked=Sum("proxy_blocked"),
                total_redacted=Sum("proxy_redacted"),
                total_secrets_resolved=Sum("secrets_resolved"),
                total_proxy_duration_ms=Sum("total_proxy_duration_ms"),
                total_proxy_calls_daemon=Sum("proxy_calls_daemon"),
                total_proxy_calls_transient=Sum("proxy_calls_transient"),
                total_proxy_calls_mcp=Sum("proxy_calls_mcp"),
                total_proxy_calls_direct=Sum("proxy_calls_direct"),
                total_developer_commands=Sum("developer_commands"),
                total_identity_anonymous_calls=Sum("identity_anonymous_calls"),
                total_identity_declared_calls=Sum("identity_declared_calls"),
                total_identity_issued_calls=Sum("identity_issued_calls"),
                total_ssrf_blocked=Sum("ssrf_attempts_blocked"),
                total_allowlist_violations=Sum("allowlist_violations"),
                total_capability_violations_blocked=Sum("capability_violations_blocked"),
                total_process_verifications_failed=Sum("process_verifications_failed"),
                total_process_verifications_passed=Sum("process_verifications_passed"),
                total_production_write_challenges=Sum("production_write_challenges"),
                avg_keychain_resolution_ms=Avg("keychain_resolution_ms"),
                avg_session_refresh_ms=Avg("session_refresh_ms"),
                total_interactive_prompts_shown=Sum("interactive_prompts_shown"),
                total_interactive_prompts_skipped=Sum("interactive_prompts_skipped"),
                total_drift_diffs_detected=Sum("drift_diffs_detected"),
                total_log_verifications=Sum("log_chain_verifications"),
                total_tampering_alerts=Sum("tampering_detected"),
                total_headless_nodes=Count("id", filter=Q(is_headless_node=True)),
                total_active_keychains=Count("id", filter=Q(keychain_initialized=True)),
                total_errors_auth=Sum("errors_auth_count"),
                total_errors_keychain=Sum("errors_keychain_count"),
                total_errors_secrets=Sum("errors_secrets_count"),
                total_errors_network=Sum("errors_network_count"),
                total_errors_system=Sum("errors_system_count"),
                total_errors_unknown=Sum("errors_unknown_count"),
            ),
        )

        active_daily = active_counts["active_daily"]
        active_weekly = active_counts["active_weekly"]
        active_monthly = active_counts["active_monthly"]

        avg_spp = (
            round(platform_state["total_secrets"] / projects_with_secrets, 1)
            if projects_with_secrets > 0
            else 0.0
        )
        avg_ppw = (
            round(platform_state["total_projects"] / platform_state["total_workspaces"], 1)
            if platform_state["total_workspaces"] > 0
            else 0.0
        )

        if platform_state["shared_workspaces"] > 0:
            avg_mpw = round(active_shared_memberships / platform_state["shared_workspaces"], 1)
        else:
            avg_mpw = 0.0

        # Unique user integration adoption
        user_integrations: Dict[str, Set[str]] = {}
        async for snapshot in TelemetrySnapshot.objects.filter(
            user__isnull=False
        ).exclude(integrations_active=[]).only("user_id", "integrations_active"):
            uid = str(snapshot.user_id)
            for integration in snapshot.integrations_active:
                if integration not in user_integrations:
                    user_integrations[integration] = set()
                user_integrations[integration].add(uid)

        total_users = platform_state["total_users"]
        integration_usage = {k: len(u_set) for k, u_set in user_integrations.items()}
        integration_adoption = {
            k: f"{round((v / total_users) * 100, 2)}%" if total_users > 0 else "0.00%"
            for k, v in integration_usage.items()
        }

        # Live Command Classification
        raw_cmd_counter = Counter()
        async for snapshot in TelemetrySnapshot.objects.exclude(command_executions={}).only(
            "command_executions"
        ):
            for cmd, count in snapshot.command_executions.items():
                raw_cmd_counter[cmd] += count

        canonical_usage, _, typos_usage = process_command_executions(raw_cmd_counter)

        total_cmds = sum(canonical_usage.values())
        command_share = {
            k: f"{round((v / total_cmds) * 100, 2)}%" if total_cmds > 0 else "0.00%"
            for k, v in canonical_usage.items()
        }

        shared_ws = platform_state["shared_workspaces"]
        team_ws = platform_state["team_workspaces"]
        team_collab = (
            f"{round((team_ws / shared_ws) * 100, 2)}%"
            if shared_ws > 0
            else "0.00%"
        )
        user_collab = (
            f"{round((users_in_shared_workspaces / total_users) * 100, 2)}%"
            if total_users > 0
            else "0.00%"
        )

        total_sec = platform_state["total_secrets"]
        prod_adoption = (
            f"{round((env_dist.get('production', 0) / total_sec) * 100, 2)}%"
            if total_sec > 0
            else "0.00%"
        )

        total_calls = proxy_agg.get("total_calls") or 0
        security_redaction = (
            f"{round(((proxy_agg.get("total_redacted") or 0) / total_calls) * 100, 2)}%"
            if total_calls > 0
            else "0.00%"
        )
        security_block = (
            f"{round(((proxy_agg.get("total_blocked") or 0) / total_calls) * 100, 2)}%"
            if total_calls > 0
            else "0.00%"
        )

        return {
            "platform": platform_state,
            "engagement": {
                "active_users_daily": active_daily,
                "active_users_weekly": active_weekly,
                "active_users_monthly": active_monthly,
                "avg_secrets_per_project": avg_spp,
                "avg_projects_per_workspace": avg_ppw,
                "avg_members_per_shared_workspace": avg_mpw,
            },
            "growth": {
                "new_signups_today": new_signups,
                "new_projects_today": new_projects,
                "new_secrets_today": new_secrets,
            },
            "analytics": {
                "stickiness_ratio_dau_mau": (
                    f"{round((active_daily / active_monthly) * 100, 2)}%"
                    if active_monthly > 0
                    else "0.00%"
                ),
                "team_collaboration_index": team_collab,
                "user_collaboration_rate": user_collab,
                "production_adoption_rate": prod_adoption,
                "security_metrics": {
                    "redaction_rate": security_redaction,
                    "block_rate": security_block,
                },
                "user_growth": {"dod": "0.00%", "wow": "0.00%", "mom": "0.00%"},
                "project_growth": {"dod": "0.00%", "wow": "0.00%", "mom": "0.00%"},
                "secret_growth": {"dod": "0.00%", "wow": "0.00%", "mom": "0.00%"},
                "dau_growth": {"dod": "0.00%", "wow": "0.00%", "mom": "0.00%"},
                "integration_adoption": integration_adoption,
                "command_market_share": command_share,
                "cli_os_distribution": os_dist,
                "unique_agents": platform_state.get("total_agents", 0),
            },
            "security": {
                "total_proxy_calls": total_calls,
                "total_proxy_blocked": proxy_agg.get("total_blocked") or 0,
                "total_proxy_redacted": proxy_agg.get("total_redacted") or 0,
                "total_secrets_resolved": proxy_agg.get("total_secrets_resolved") or 0,
            },
            "agent_infrastructure": {
                "execution_paths": {
                    "daemon": proxy_agg.get("total_proxy_calls_daemon") or 0,
                    "transient": proxy_agg.get("total_proxy_calls_transient") or 0,
                    "mcp": proxy_agg.get("total_proxy_calls_mcp") or 0,
                    "direct": proxy_agg.get("total_proxy_calls_direct") or 0,
                    "developer": proxy_agg.get("total_developer_commands") or 0,
                },
                "identity_levels": {
                    "anonymous": proxy_agg.get("total_identity_anonymous_calls") or 0,
                    "declared": proxy_agg.get("total_identity_declared_calls") or 0,
                    "issued": proxy_agg.get("total_identity_issued_calls") or 0,
                },
                "shielding": {
                    "ssrf_blocked": proxy_agg.get("total_ssrf_blocked") or 0,
                    "allowlist_violations": proxy_agg.get("total_allowlist_violations") or 0,
                    "capability_violations": proxy_agg.get("total_capability_violations_blocked") or 0,
                    "process_verifications_failed": proxy_agg.get("total_process_verifications_failed") or 0,
                    "process_verifications_passed": proxy_agg.get("total_process_verifications_passed") or 0,
                    "production_write_challenges": proxy_agg.get("total_production_write_challenges") or 0,
                },
            },
            "performance": {
                "avg_keychain_resolution_ms": proxy_agg.get("avg_keychain_resolution_ms") or 0.0,
                "avg_session_refresh_ms": proxy_agg.get("avg_session_refresh_ms") or 0.0,
                "total_proxy_duration_ms": proxy_agg.get("total_proxy_duration_ms") or 0,
            },
            "integrity": {
                "log_chain_verifications": proxy_agg.get("total_log_verifications") or 0,
                "tampering_alerts": proxy_agg.get("total_tampering_alerts") or 0,
                "active_keychains": proxy_agg.get("total_active_keychains") or 0,
                "headless_nodes": proxy_agg.get("total_headless_nodes") or 0,
            },
            "friction": {
                "interactive_prompts_shown": proxy_agg.get("total_interactive_prompts_shown") or 0,
                "interactive_prompts_skipped": proxy_agg.get("total_interactive_prompts_skipped") or 0,
                "drift_diffs_detected": proxy_agg.get("total_drift_diffs_detected") or 0,
            },
            "errors": {
                "auth": proxy_agg.get("total_errors_auth") or 0,
                "keychain": proxy_agg.get("total_errors_keychain") or 0,
                "secrets": proxy_agg.get("total_errors_secrets") or 0,
                "network": proxy_agg.get("total_errors_network") or 0,
                "system": proxy_agg.get("total_errors_system") or 0,
                "unknown": proxy_agg.get("total_errors_unknown") or 0,
            },
            "feature_adoption": {
                "environment_distribution": env_dist,
                "command_usage": canonical_usage,
                "integration_usage": integration_usage,
                "typos_usage": typos_usage,
            },
            "report_date": str(today),
            "computed_at": timezone.now().isoformat(),
        }
