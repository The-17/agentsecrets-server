# Standard library
import hmac
import json
import logging

# Django
from django.conf import settings
from django.core.cache import cache
from django.db.models import Count, Sum, Q
from django.utils import timezone

# Third-party
from asgiref.sync import sync_to_async
from django.core.management import call_command
from ninja_extra import api_controller, route
from pydantic import TypeAdapter

# Local
from apps.accounts.models import User
from apps.common.response import CustomResponse
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipStatus, AgentRegistration
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import TelemetrySnapshot, DailyMetricsAggregate
from .schemas import TelemetrySyncSchema


logger = logging.getLogger("apps.telemetry")

# Pydantic TypeAdapter for validating a list of telemetry snapshots
_sync_list_adapter = TypeAdapter(list[TelemetrySyncSchema])


@api_controller("/", tags=["Telemetry"], auth=None)
class TelemetryController:
    """
    Telemetry ingestion and metrics controller.

    Replaces the previous DRF-based telemetry views with native
    Django Ninja endpoints for consistency and performance.
    """

    # ──────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────

    @staticmethod
    def _soft_authenticate(request):
        """
        Try to authenticate with JWT. If the token is invalid or expired,
        gracefully return None (anonymous) instead of raising 401.
        """
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header[7:]
        try:
            jwt_auth = JWTAuthentication()
            validated_token = jwt_auth.get_validated_token(token)
            user = jwt_auth.get_user(validated_token)
            return user
        except (InvalidToken, TokenError):
            return None
        except Exception:
            return None

    @staticmethod
    def _check_rate_limit(request, user):
        """
        Cache-backed rate limiting: 5/day anonymous, 20/day authenticated.
        Returns True if the request is allowed, False if rate-limited.
        """
        if user:
            key = f"rl_telemetry_user_{user.id}"
            limit = 20
        else:
            ip = request.META.get("REMOTE_ADDR", "unknown")
            key = f"rl_telemetry_anon_{ip}"
            limit = 5

        current = cache.get(key, 0)
        if current >= limit:
            return False
        cache.set(key, current + 1, 86400)  # 24-hour window
        return True

    # ──────────────────────────────────────────────
    # POST /sync/
    # ──────────────────────────────────────────────

    @route.post("/sync/", response={200: dict, 429: dict})
    async def sync(self, request):
        """
        Receive batched CLI telemetry data.

        The CLI collects telemetry locally and syncs every 24 hours.
        This endpoint stores the payload for aggregation and analysis.
        """
        # ── AUTH (soft — anonymous fallback) ──
        user = await sync_to_async(self._soft_authenticate)(request)

        # ── RATE LIMIT ──
        allowed = await sync_to_async(self._check_rate_limit)(request, user)
        if not allowed:
            return CustomResponse.error(
                message="Rate limit exceeded. Try again tomorrow.",
                code="rate_limited",
                status_code=429,
            )

        # ──────────────────────────────────────────────
        # 1. FORMAT DETECTION & TRANSFORMATION
        #    Handles multiple formats for maximum compatibility:
        #    A) Final CLI Batch: {"snapshots": [...]}
        #    B) Intermediate Batch: {"daily": {"YYYY-MM-DD": {...}, ...}}
        #    C) Generic Batch: [{...}, {...}]
        #    D) Legacy Single: {...}
        # ──────────────────────────────────────────────
        body = json.loads(request.body)

        if isinstance(body, dict) and "snapshots" in body:
            payload = body["snapshots"]
        elif isinstance(body, dict) and "daily" in body:
            payload = []
            for date_str, snapshot_data in body["daily"].items():
                snapshot_data["date"] = date_str
                payload.append(snapshot_data)
        else:
            payload = body if isinstance(body, list) else [body]

        # ── VALIDATE with Pydantic ──
        validated_items = _sync_list_adapter.validate_python(payload)

        # ──────────────────────────────────────────────
        # 1b. USER ATTRIBUTION
        #     If the JWT is expired (soft auth returns None), fall back
        #     to user_email from the payload. Bulk-fetch all emails in one query.
        # ──────────────────────────────────────────────
        email_to_user = {}
        if not user:
            emails = {item.user_email for item in validated_items if item.user_email}
            if emails:
                async for u in User.objects.filter(email__in=emails):
                    email_to_user[u.email] = u

        # ──────────────────────────────────────────────
        # 2. BATCH ENRICHMENT (DB Efficiency)
        #    Collect all IDs and perform bulk counts to avoid connection exhaustion.
        # ──────────────────────────────────────────────
        ws_ids = {item.workspace_id for item in validated_items if item.workspace_id}
        prj_ids = {item.project_id for item in validated_items if item.project_id}

        # Determine the earliest date in the batch to limit our lookups
        all_dates = []
        for item in validated_items:
            dt = item.date or (item.timestamp.date() if item.timestamp else timezone.now().date())
            all_dates.append(dt)
        min_date = min(all_dates) if all_dates else timezone.now().date()

        # Pre-fetch counts for all workspaces and projects in the batch
        # This reduces DB round-trips from 2*N to just 2 per request.
        ws_counts = {}
        if ws_ids:
            ws_qs = (
                Membership.objects
                .filter(workspace_id__in=ws_ids, status=MembershipStatus.ACTIVE, created_at__date__lte=timezone.now().date())
                .values('workspace_id')
                .annotate(count=Count('id'))
            )
            async for entry in ws_qs:
                ws_counts[entry['workspace_id']] = entry['count']

        prj_counts = {}
        if prj_ids:
            prj_qs = (
                Secret.objects
                .filter(project_id__in=prj_ids, created_at__date__lte=timezone.now().date())
                .values('project_id')
                .annotate(count=Count('id'))
            )
            async for entry in prj_qs:
                prj_counts[entry['project_id']] = entry['count']

        # ──────────────────────────────────────────────
        # 3. BATCH DEFAULTS & SNAPSHOT CREATION
        #    Handle sparse payloads by inheriting values from the batch
        # ──────────────────────────────────────────────
        batch_user_email = next((item.user_email for item in validated_items if item.user_email), None)
        batch_cli_version = next((item.cli_version for item in validated_items if item.cli_version), None)
        batch_os = next((item.os for item in validated_items if item.os), None)
        batch_arch = next((item.arch for item in validated_items if item.arch), None)

        snapshots = []
        for item in validated_items:
            # Determine the effective date and timestamp
            target_date = item.date
            client_ts = item.timestamp

            if target_date:
                from datetime import datetime, time
                client_ts = timezone.make_aware(datetime.combine(target_date, time.min))
            elif not client_ts:
                client_ts = timezone.now()

            ws_id = item.workspace_id
            prj_id = item.project_id

            # Resolve user: JWT auth takes priority, then email fallback
            item_email = item.user_email or batch_user_email
            snapshot_user = user or email_to_user.get(item_email)

            snapshots.append(TelemetrySnapshot(
                user=snapshot_user,
                cli_version=item.cli_version or batch_cli_version,
                os=item.os or batch_os,
                arch=item.arch or batch_arch,
                command_executions=item.command_executions or {},
                active_environment=item.active_environment,
                workspace_type=item.workspace_type,
                workspace_member_count=ws_counts.get(ws_id, item.workspace_member_count or 0),
                project_secret_count=prj_counts.get(prj_id, item.project_secret_count or 0),
                proxy_calls=item.proxy_calls,
                proxy_blocked=item.proxy_blocked,
                proxy_redacted=item.proxy_redacted,
                injection_styles_used=item.injection_styles_used or [],
                integrations_active=item.integrations_active or [],
                secrets_resolved=item.secrets_resolved,
                total_proxy_duration_ms=item.total_proxy_duration_ms,
                proxy_calls_daemon=item.proxy_calls_daemon,
                proxy_calls_transient=item.proxy_calls_transient,
                proxy_calls_mcp=item.proxy_calls_mcp,
                proxy_calls_direct=item.proxy_calls_direct,
                developer_commands=item.developer_commands,
                ssrf_attempts_blocked=item.ssrf_attempts_blocked,
                allowlist_violations=item.allowlist_violations,
                response_redactions=item.response_redactions,
                process_verifications_failed=item.process_verifications_failed,
                production_write_challenges=item.production_write_challenges,
                keychain_resolution_ms=item.keychain_resolution_ms,
                session_refresh_ms=item.session_refresh_ms,
                interactive_prompts_shown=item.interactive_prompts_shown,
                interactive_prompts_skipped=item.interactive_prompts_skipped,
                drift_diffs_detected=item.drift_diffs_detected,
                log_chain_verifications=item.log_chain_verifications,
                tampering_detected=item.tampering_detected,
                is_headless_node=item.is_headless_node,
                keychain_initialized=item.keychain_initialized,
                typos=item.typos or {},
                identity_anonymous_calls=item.identity_anonymous_calls,
                identity_declared_calls=item.identity_declared_calls,
                identity_issued_calls=item.identity_issued_calls,
                capability_violations_blocked=item.capability_violations_blocked,
                process_verifications_passed=item.process_verifications_passed,
                errors_auth_count=item.errors_auth_count,
                errors_keychain_count=item.errors_keychain_count,
                errors_secrets_count=item.errors_secrets_count,
                errors_network_count=item.errors_network_count,
                errors_system_count=item.errors_system_count,
                errors_unknown_count=item.errors_unknown_count,
                client_timestamp=client_ts,
            ))

        # ──────────────────────────────────────────────
        # 4. DEDUP & UPSERT
        #    Deduplicate by (user, client_timestamp date) to prevent
        #    stale CLI re-sends from creating duplicate rows.
        # ──────────────────────────────────────────────
        created_count = 0
        updated_count = 0
        for snap in snapshots:
            ts_date = snap.client_timestamp.date() if snap.client_timestamp else None
            existing = None
            if snap.user and ts_date:
                existing = await TelemetrySnapshot.objects.filter(
                    user=snap.user,
                    client_timestamp__date=ts_date,
                ).afirst()

            if existing:
                # Update all metric fields on the existing row
                for field in TelemetrySnapshot._meta.get_fields():
                    if not hasattr(field, 'attname') or field.attname in ('id', 'created_at', 'updated_at', 'user_id', 'client_timestamp'):
                        continue
                    setattr(existing, field.attname, getattr(snap, field.attname))
                await existing.asave()
                updated_count += 1
            else:
                await snap.asave()
                created_count += 1

        # Log with attribution source for debugging
        if user:
            user_label = user.email
        elif email_to_user:
            user_label = f"{list(email_to_user.keys())[0]} (via email)"
        else:
            user_label = "anonymous"
        logger.info(f"Telemetry sync from {user_label}: {created_count} created, {updated_count} updated")

        return CustomResponse.success(
            message="Telemetry synced successfully",
            status_code=200,
        )

    # ──────────────────────────────────────────────
    # GET /metrics/
    # ──────────────────────────────────────────────

    @route.get("/metrics/", response={200: dict})
    async def metrics(self, request, bypass_cache: bool = False):
        """
        Public metrics endpoint for the AgentSecrets website and internal dashboards.

        Returns the full platform report:
        - Platform state: total users, projects, secrets, workspaces (from real models)
        - Engagement: active users (rolling 7d, 30d), averages
        - Growth: new signups, projects, secrets (today's delta)
        - Security: cumulative proxy stats across all time
        - Feature adoption: command usage, integrations, env distribution
        - Analytics: stickiness, collaboration, growth rates

        Uses the latest DailyMetricsAggregate if available (computed by cron).
        Falls back to live queries if no aggregate exists.
        """
        cache_key = "public_platform_metrics"

        if not bypass_cache:
            cached_data = await sync_to_async(cache.get)(cache_key)
            if cached_data:
                return CustomResponse.success(
                    message="Platform metrics report",
                    data=cached_data,
                    status_code=200,
                )

        import asyncio
        from datetime import timedelta
        today = timezone.now().date()

        # 1. ALWAYS get live platform state, today's metrics and historical comparison aggregates concurrently
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
            os_dist
        ) = await asyncio.gather(
            self._get_live_platform_state(),
            self._get_live_env_distribution(),
            self._get_today_live_metrics(today),
            DailyMetricsAggregate.objects.order_by('-date').afirst(),
            DailyMetricsAggregate.objects.filter(date__lte=yesterday_date).order_by('-date').afirst(),
            DailyMetricsAggregate.objects.filter(date__lte=week_ago_date).order_by('-date').afirst(),
            DailyMetricsAggregate.objects.filter(date__lte=month_ago_date).order_by('-date').afirst(),
            self._get_live_os_distribution(),
        )

        if latest:
            # Calculate stickiness (DAU/MAU)
            dau = today_metrics['active_users_daily']
            mau = today_metrics['active_users_monthly']
            stickiness = f"{round((dau / mau) * 100, 2)}%" if mau > 0 else "0.00%"

            # Collaboration Index (Team Workspaces / Total Workspaces)
            total_ws = platform_state['total_workspaces']
            team_collab = f"{round((platform_state['team_workspaces'] / total_ws) * 100, 2)}%" if total_ws > 0 else "0.00%"

            # Production Adoption Rate (Production Secrets / Total Secrets)
            total_secrets = platform_state['total_secrets']
            prod_adoption = f"{round((env_dist.get('production', 0) / total_secrets) * 100, 2)}%" if total_secrets > 0 else "0.00%"

            # Security Redaction & Block Rates
            total_calls = latest.total_proxy_calls
            security_redaction = f"{round((latest.total_proxy_redacted / total_calls) * 100, 2)}%" if total_calls > 0 else "0.00%"
            security_block = f"{round((latest.total_proxy_blocked / total_calls) * 100, 2)}%" if total_calls > 0 else "0.00%"

            # Integration adoption from aggregate (percentage of total registered users using it)
            total_users = platform_state['total_users']
            integration_adoption = {}
            for integration, count in latest.integration_usage.items():
                pct = round((count / total_users) * 100, 2) if total_users > 0 else 0.0
                integration_adoption[integration] = f"{pct}%"

            # Command share from aggregate
            command_usage = latest.command_usage
            total_cmds = sum(command_usage.values())
            command_share = {}
            for cmd, count in command_usage.items():
                pct = round((count / total_cmds) * 100, 2) if total_cmds > 0 else 0.0
                command_share[cmd] = f"{pct}%"

            # Calculate growth helper
            def _growth(curr, past_agg, field):
                if not past_agg:
                    return "0.00%"
                past_val = getattr(past_agg, field, 0)
                if past_val == 0:
                    return "0.00%"
                pct = round(((curr - past_val) / past_val) * 100, 2)
                prefix = "+" if pct > 0 else ""
                return f"{prefix}{pct}%"

            analytics = {
                'stickiness_ratio_dau_mau': stickiness,
                'team_collaboration_index': team_collab,
                'production_adoption_rate': prod_adoption,
                'security_metrics': {
                    'redaction_rate': security_redaction,
                    'block_rate': security_block,
                },
                'user_growth': {
                    'dod': _growth(platform_state['total_users'], agg_yesterday, 'total_users'),
                    'wow': _growth(platform_state['total_users'], agg_week_ago, 'total_users'),
                    'mom': _growth(platform_state['total_users'], agg_month_ago, 'total_users'),
                },
                'project_growth': {
                    'dod': _growth(platform_state['total_projects'], agg_yesterday, 'total_projects'),
                    'wow': _growth(platform_state['total_projects'], agg_week_ago, 'total_projects'),
                    'mom': _growth(platform_state['total_projects'], agg_month_ago, 'total_projects'),
                },
                'secret_growth': {
                    'dod': _growth(platform_state['total_secrets'], agg_yesterday, 'total_secrets'),
                    'wow': _growth(platform_state['total_secrets'], agg_week_ago, 'total_secrets'),
                    'mom': _growth(platform_state['total_secrets'], agg_month_ago, 'total_secrets'),
                },
                'dau_growth': {
                    'dod': _growth(dau, agg_yesterday, 'active_users_daily'),
                    'wow': _growth(dau, agg_week_ago, 'active_users_daily'),
                    'mom': _growth(dau, agg_month_ago, 'active_users_daily'),
                },
                'integration_adoption': integration_adoption,
                'command_market_share': command_share,
                'cli_os_distribution': os_dist,
                'unique_agents': platform_state.get('total_agents', 0),
            }
            data = self._build_from_aggregate(latest, platform_state, env_dist, today_metrics, today, analytics)
        else:
            data = await self._build_live(platform_state, env_dist, os_dist)

        return CustomResponse.success(
            message="Platform metrics report",
            data=data,
            status_code=200,
        )

    async def _get_live_platform_state(self):
        import asyncio
        # Count secret-level policies (non-null, non-empty policy JSONField)
        # and agent capability policies (non-null, non-empty capabilities JSONField)
        # separately then sum, to avoid a cross-model join.
        secret_policies, agent_policies = await asyncio.gather(
            Secret.objects.exclude(policy__isnull=True).exclude(policy__exact={}).acount(),
            AgentRegistration.objects.exclude(capabilities__isnull=True).exclude(capabilities__exact={}).acount(),
        )
        return {
            'total_users': await User.objects.acount(),
            'total_projects': await Project.objects.acount(),
            'total_secrets': await Secret.objects.acount(),
            'total_workspaces': await Workspace.objects.acount(),
            'shared_workspaces': await Workspace.objects.filter(type=WorkspaceType.SHARED).acount(),
            'team_workspaces': await Workspace.objects.filter(
                type=WorkspaceType.SHARED
            ).annotate(
                active_members=Count('memberships', filter=Q(memberships__status=MembershipStatus.ACTIVE))
            ).filter(active_members__gt=1).acount(),
            'pending_invites': await Membership.objects.filter(status=MembershipStatus.INVITED).acount(),
            'total_agents': await AgentRegistration.objects.acount(),
            # total_policies = secret-level policies + agent capability policies
            'total_policies': secret_policies + agent_policies,
        }

    async def _get_live_env_distribution(self):
        return {
            'development': await Secret.objects.filter(environment='development').acount(),
            'staging': await Secret.objects.filter(environment='staging').acount(),
            'production': await Secret.objects.filter(environment='production').acount(),
        }

    async def _get_live_os_distribution(self):
        qs = TelemetrySnapshot.objects.values('os').annotate(unique_users=Count('user', distinct=True)).order_by('-unique_users')
        results = {}
        total = 0
        async for item in qs:
            os_name = item['os'] or 'unknown'
            count = item['unique_users']
            results[os_name] = count
            total += count

        if total > 0:
            return {os_name: f"{round((count / total) * 100, 2)}%" for os_name, count in results.items()}
        return {}

    async def _get_today_live_metrics(self, today):
        import asyncio
        from datetime import timedelta
        now = timezone.now()
        rolling_daily = now - timedelta(hours=24)
        rolling_weekly = now - timedelta(days=7)
        rolling_monthly = now - timedelta(days=30)

        (
            active_counts,
            new_signups,
            new_projects,
            new_secrets
        ) = await asyncio.gather(
            User.objects.aaggregate(
                active_daily=Count('id', filter=Q(last_active_at__gte=rolling_daily)),
                active_weekly=Count('id', filter=Q(last_active_at__gte=rolling_weekly)),
                active_monthly=Count('id', filter=Q(last_active_at__gte=rolling_monthly))
            ),
            User.objects.filter(created_at__date=today).acount(),
            Project.objects.filter(created_at__date=today).acount(),
            Secret.objects.filter(created_at__date=today).acount(),
        )
        return {
            'active_users_daily': active_counts['active_daily'],
            'active_users_weekly': active_counts['active_weekly'],
            'active_users_monthly': active_counts['active_monthly'],
            'new_signups_today': new_signups,
            'new_projects_today': new_projects,
            'new_secrets_today': new_secrets,
        }

    def _build_from_aggregate(self, agg, platform_state, env_dist, today_metrics, today, analytics):
        """Build response mixing live platform state and today's live activity with pre-computed heavy aggregates and analytics.

        platform_state is always fetched live (includes total_policies computed fresh),
        so the aggregate path surfaces an accurate policy count without needing it in the
        DailyMetricsAggregate table.
        """
        return {
            'platform': platform_state,
            'engagement': {
                'active_users_daily': today_metrics['active_users_daily'],
                'active_users_weekly': today_metrics['active_users_weekly'],
                'active_users_monthly': today_metrics['active_users_monthly'],
                'avg_secrets_per_project': agg.avg_secrets_per_project,
                'avg_projects_per_workspace': agg.avg_projects_per_workspace,
                'avg_members_per_shared_workspace': agg.avg_members_per_workspace,
            },
            'growth': {
                'new_signups_today': today_metrics['new_signups_today'],
                'new_projects_today': today_metrics['new_projects_today'],
                'new_secrets_today': today_metrics['new_secrets_today'],
            },
            'analytics': analytics,
            'security': {
                'total_proxy_calls': agg.total_proxy_calls,
                'total_proxy_blocked': agg.total_proxy_blocked,
                'total_proxy_redacted': agg.total_proxy_redacted,
                'total_secrets_resolved': agg.total_secrets_resolved,
            },
            'agent_infrastructure': {
                'execution_paths': {
                    'daemon': agg.total_proxy_calls_daemon,
                    'transient': agg.total_proxy_calls_transient,
                    'mcp': agg.total_proxy_calls_mcp,
                    'direct': agg.total_proxy_calls_direct,
                    'developer': agg.total_developer_commands,
                },
                'identity_levels': {
                    'anonymous': agg.total_identity_anonymous_calls,
                    'declared': agg.total_identity_declared_calls,
                    'issued': agg.total_identity_issued_calls,
                },
                'shielding': {
                    'ssrf_blocked': agg.total_ssrf_blocked,
                    'allowlist_violations': agg.total_allowlist_violations,
                    'capability_violations': agg.total_capability_violations_blocked,
                    'process_verifications_failed': agg.total_process_verifications_failed,
                    'process_verifications_passed': agg.total_process_verifications_passed,
                }
            },
            'feature_adoption': {
                'environment_distribution': env_dist,
                'command_usage': agg.command_usage,
                'integration_usage': agg.integration_usage,
                'typos_usage': agg.typos_usage,
            },
            'report_date': str(today),
            'computed_at': timezone.now().isoformat(),
        }

    async def _build_live(self, platform_state, env_dist, os_dist):
        """Fallback: compute heavy metrics live from the database."""
        import asyncio
        from datetime import timedelta

        now = timezone.now()
        today = now.date()
        rolling_daily = now - timedelta(hours=24)
        rolling_weekly = now - timedelta(days=7)
        rolling_monthly = now - timedelta(days=30)

        # Run independent database queries concurrently
        (
            active_counts,
            projects_with_secrets,
            active_shared_memberships,
            new_signups,
            new_projects,
            new_secrets,
            proxy_agg
        ) = await asyncio.gather(
            User.objects.aaggregate(
                active_daily=Count('id', filter=Q(last_active_at__gte=rolling_daily)),
                active_weekly=Count('id', filter=Q(last_active_at__gte=rolling_weekly)),
                active_monthly=Count('id', filter=Q(last_active_at__gte=rolling_monthly))
            ),
            Project.objects.filter(secrets__isnull=False).distinct().acount(),
            Membership.objects.filter(workspace__type=WorkspaceType.SHARED, status=MembershipStatus.ACTIVE).acount(),
            User.objects.filter(created_at__date=today).acount(),
            Project.objects.filter(created_at__date=today).acount(),
            Secret.objects.filter(created_at__date=today).acount(),
            TelemetrySnapshot.objects.aaggregate(
                total_calls=Sum('proxy_calls'),
                total_blocked=Sum('proxy_blocked'),
                total_redacted=Sum('proxy_redacted'),
                total_secrets_resolved=Sum('secrets_resolved'),
                total_proxy_calls_daemon=Sum('proxy_calls_daemon'),
                total_proxy_calls_transient=Sum('proxy_calls_transient'),
                total_proxy_calls_mcp=Sum('proxy_calls_mcp'),
                total_proxy_calls_direct=Sum('proxy_calls_direct'),
                total_developer_commands=Sum('developer_commands'),
                total_identity_anonymous_calls=Sum('identity_anonymous_calls'),
                total_identity_declared_calls=Sum('identity_declared_calls'),
                total_identity_issued_calls=Sum('identity_issued_calls'),
                total_ssrf_blocked=Sum('ssrf_attempts_blocked'),
                total_allowlist_violations=Sum('allowlist_violations'),
                total_capability_violations_blocked=Sum('capability_violations_blocked'),
                total_process_verifications_failed=Sum('process_verifications_failed'),
                total_process_verifications_passed=Sum('process_verifications_passed')
            )
        )

        active_daily = active_counts['active_daily']
        active_weekly = active_counts['active_weekly']
        active_monthly = active_counts['active_monthly']

        # Averages
        avg_spp = round(platform_state['total_secrets'] / projects_with_secrets, 1) if projects_with_secrets > 0 else 0.0
        avg_ppw = round(platform_state['total_projects'] / platform_state['total_workspaces'], 1) if platform_state['total_workspaces'] > 0 else 0.0

        if platform_state['shared_workspaces'] > 0:
            avg_mpw = round(active_shared_memberships / platform_state['shared_workspaces'], 1)
        else:
            avg_mpw = 0.0

        # Live integration & command usage scan
        integration_usage = {}
        async for snapshot in TelemetrySnapshot.objects.exclude(integrations_active=[]).only('integrations_active'):
            for integration in snapshot.integrations_active:
                integration_usage[integration] = integration_usage.get(integration, 0) + 1

        total_users = platform_state['total_users']
        integration_adoption = {
            k: f"{round((v / total_users) * 100, 2)}%" if total_users > 0 else "0.00%"
            for k, v in integration_usage.items()
        }

        VALID_COMMANDS = {
            'root', 'init', 'login', 'logout', 'status', 'workspace', 'project',
            'secrets', 'agent', 'log', 'proxy', 'mcp', 'call', 'environment',
            'env', 'exec', 'docs', '-h', '-v', '--help', '--version'
        }
        command_usage = {}
        typos_usage = {}
        async for snapshot in TelemetrySnapshot.objects.exclude(command_executions={}).only('command_executions'):
            for cmd, count in snapshot.command_executions.items():
                if cmd in VALID_COMMANDS:
                    command_usage[cmd] = command_usage.get(cmd, 0) + count
                else:
                    typos_usage[cmd] = typos_usage.get(cmd, 0) + count

        total_cmds = sum(command_usage.values())
        command_share = {
            k: f"{round((v / total_cmds) * 100, 2)}%" if total_cmds > 0 else "0.00%"
            for k, v in command_usage.items()
        }
        # Collaboration & adoption rates
        total_ws = platform_state['total_workspaces']
        team_collab = f"{round((platform_state['team_workspaces'] / total_ws) * 100, 2)}%" if total_ws > 0 else "0.00%"

        total_sec = platform_state['total_secrets']
        prod_adoption = f"{round((env_dist.get('production', 0) / total_sec) * 100, 2)}%" if total_sec > 0 else "0.00%"

        total_calls = proxy_agg.get('total_calls') or 0
        security_redaction = f"{round(((proxy_agg.get('total_redacted') or 0) / total_calls) * 100, 2)}%" if total_calls > 0 else "0.00%"
        security_block = f"{round(((proxy_agg.get('total_blocked') or 0) / total_calls) * 100, 2)}%" if total_calls > 0 else "0.00%"

        return {
            'platform': platform_state,
            'engagement': {
                'active_users_daily': active_daily,
                'active_users_weekly': active_weekly,
                'active_users_monthly': active_monthly,
                'avg_secrets_per_project': avg_spp,
                'avg_projects_per_workspace': avg_ppw,
                'avg_members_per_shared_workspace': avg_mpw,
            },
            'growth': {
                'new_signups_today': new_signups,
                'new_projects_today': new_projects,
                'new_secrets_today': new_secrets,
            },
            'analytics': {
                'stickiness_ratio_dau_mau': f"{round((active_daily / active_monthly) * 100, 2)}%" if active_monthly > 0 else "0.00%",
                'team_collaboration_index': team_collab,
                'production_adoption_rate': prod_adoption,
                'security_metrics': {
                    'redaction_rate': security_redaction,
                    'block_rate': security_block,
                },
                'user_growth': {'dod': "0.00%", 'wow': "0.00%", 'mom': "0.00%"},
                'project_growth': {'dod': "0.00%", 'wow': "0.00%", 'mom': "0.00%"},
                'secret_growth': {'dod': "0.00%", 'wow': "0.00%", 'mom': "0.00%"},
                'dau_growth': {'dod': "0.00%", 'wow': "0.00%", 'mom': "0.00%"},
                'integration_adoption': integration_adoption,
                'command_market_share': command_share,
                'cli_os_distribution': os_dist,
                'unique_agents': platform_state.get('total_agents', 0),
            },
            'security': {
                'total_proxy_calls': total_calls,
                'total_proxy_blocked': proxy_agg.get('total_blocked') or 0,
                'total_proxy_redacted': proxy_agg.get('total_redacted') or 0,
                'total_secrets_resolved': proxy_agg.get('total_secrets_resolved') or 0,
            },
            'agent_infrastructure': {
                'execution_paths': {
                    'daemon': proxy_agg.get('total_proxy_calls_daemon') or 0,
                    'transient': proxy_agg.get('total_proxy_calls_transient') or 0,
                    'mcp': proxy_agg.get('total_proxy_calls_mcp') or 0,
                    'direct': proxy_agg.get('total_proxy_calls_direct') or 0,
                    'developer': proxy_agg.get('total_developer_commands') or 0,
                },
                'identity_levels': {
                    'anonymous': proxy_agg.get('total_identity_anonymous_calls') or 0,
                    'declared': proxy_agg.get('total_identity_declared_calls') or 0,
                    'issued': proxy_agg.get('total_identity_issued_calls') or 0,
                },
                'shielding': {
                    'ssrf_blocked': proxy_agg.get('total_ssrf_blocked') or 0,
                    'allowlist_violations': proxy_agg.get('total_allowlist_violations') or 0,
                    'capability_violations': proxy_agg.get('total_capability_violations_blocked') or 0,
                    'process_verifications_failed': proxy_agg.get('total_process_verifications_failed') or 0,
                    'process_verifications_passed': proxy_agg.get('total_process_verifications_passed') or 0,
                }
            },
            'feature_adoption': {
                'environment_distribution': env_dist,
                'command_usage': command_usage,
                'integration_usage': integration_usage,
                'typos_usage': typos_usage,
            },
            'report_date': str(today),
            'computed_at': timezone.now().isoformat(),
        }

    # ──────────────────────────────────────────────
    # GET/POST /internal/compute-metrics/
    # ──────────────────────────────────────────────

    @route.get("/internal/compute-metrics/", response={200: dict, 401: dict, 500: dict})
    async def compute_metrics_get(self, request):
        """Vercel cron calls GET by default."""
        return await self._handle_cron(request)

    @route.post("/internal/compute-metrics/", response={200: dict, 401: dict, 500: dict})
    async def compute_metrics_post(self, request):
        return await self._handle_cron(request)

    async def _handle_cron(self, request):
        """
        Internal trigger for Vercel Cron to calculate daily metrics.

        Vercel sends CRON_SECRET via the Authorization header.
        """
        if not self._verify_cron_secret(request):
            return CustomResponse.error(
                message="Unauthorized cron trigger",
                status_code=401,
            )

        try:
            await sync_to_async(call_command)('calculate_metrics')
            return CustomResponse.success(message="Metrics calculated successfully")
        except Exception as e:
            logger.error(f"Cron metrics calculation failed: {str(e)}")
            return CustomResponse.error(message="Metrics calculation failed", status_code=500)

    @staticmethod
    def _verify_cron_secret(request):
        """Verify the Vercel CRON_SECRET from the Authorization header."""
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return False
        token = auth_header[7:]  # Strip 'Bearer '
        expected = getattr(settings, 'CRON_SECRET', 'dev-secret')
        return hmac.compare_digest(token, expected)
