# Standard library
import logging

# Django
from django.db.models import Count, Sum, Q
from django.utils import timezone

# Third-party
from adrf.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken

# Local
from asgiref.sync import sync_to_async
from django.core.management import call_command
from django.conf import settings
from apps.common.response import CustomResponse
from apps.accounts.models import User
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipStatus
from .models import TelemetrySnapshot, DailyMetricsAggregate
from .serializers import TelemetrySyncSerializer, PublicMetricsSerializer


logger = logging.getLogger("apps.telemetry")


class SoftJWTAuthentication(JWTAuthentication):
    """
    Tries to authenticate with JWT. If the token is invalid or expired,
    it gracefully returns None (falling back to AnonymousUser) instead
    of throwing an AuthenticationFailed exception.
    """
    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except (InvalidToken, AuthenticationFailed):
            return None


class TelemetrySyncAPIView(APIView):
    """
    Receive batched CLI telemetry data.
    
    The CLI collects telemetry locally and syncs every 24 hours.
    This endpoint stores the payload for aggregation and analysis.
    """
    authentication_classes = [SoftJWTAuthentication]
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    serializer_class = TelemetrySyncSerializer

    async def post(self, request):
        # ──────────────────────────────────────────────
        # 1. FORMAT DETECTION & TRANSFORMATION
        #    Handles multiple formats for maximum compatibility:
        #    A) Final CLI Batch: {"snapshots": [...]}
        #    B) Intermediate Batch: {"daily": {"YYYY-MM-DD": {...}, ...}}
        #    C) Generic Batch: [{...}, {...}]
        #    D) Legacy Single: {...}
        # ──────────────────────────────────────────────
        if isinstance(request.data, dict) and "snapshots" in request.data:
            payload = request.data["snapshots"]
        elif isinstance(request.data, dict) and "daily" in request.data:
            payload = []
            for date_str, snapshot_data in request.data["daily"].items():
                snapshot_data["date"] = date_str
                payload.append(snapshot_data)
        else:
            payload = request.data if isinstance(request.data, list) else [request.data]

        serializer = self.serializer_class(data=payload, many=True)
        serializer.is_valid(raise_exception=True)
        
        user = request.user if request.user.is_authenticated else None
        
        # ──────────────────────────────────────────────
        # 1b. USER ATTRIBUTION
        #     If the JWT is expired (SoftJWTAuth returns anonymous), fall back
        #     to user_email from the payload. Bulk-fetch all emails in one query.
        # ──────────────────────────────────────────────
        email_to_user = {}
        if not user:
            emails = {item.get('user_email') for item in serializer.validated_data if item.get('user_email')}
            if emails:
                async for u in User.objects.filter(email__in=emails):
                    email_to_user[u.email] = u

        snapshots = []
        # ──────────────────────────────────────────────
        # 2. BATCH ENRICHMENT (DB Efficiency)
        #    Collect all IDs and perform bulk counts to avoid connection exhaustion.
        # ──────────────────────────────────────────────
        ws_ids = {item.get('workspace_id') for item in serializer.validated_data if item.get('workspace_id')}
        prj_ids = {item.get('project_id') for item in serializer.validated_data if item.get('project_id')}
        
        # Determine the earliest date in the batch to limit our lookups
        all_dates = []
        for item in serializer.validated_data:
            dt = item.get('date') or (item.get('timestamp').date() if item.get('timestamp') else timezone.now().date())
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
        batch_user_email = next((item.get('user_email') for item in serializer.validated_data if item.get('user_email')), None)
        batch_cli_version = next((item.get('cli_version') for item in serializer.validated_data if item.get('cli_version')), None)
        batch_os = next((item.get('os') for item in serializer.validated_data if item.get('os')), None)
        batch_arch = next((item.get('arch') for item in serializer.validated_data if item.get('arch')), None)

        snapshots = []
        for item in serializer.validated_data:
            # Determine the effective date and timestamp
            target_date = item.get('date')
            client_ts = item.get('timestamp')

            if target_date:
                from datetime import datetime, time
                client_ts = timezone.make_aware(datetime.combine(target_date, time.min))
            elif not client_ts:
                client_ts = timezone.now()
            
            ws_id = item.get('workspace_id')
            prj_id = item.get('project_id')

            # Resolve user: JWT auth takes priority, then email fallback
            item_email = item.get('user_email') or batch_user_email
            snapshot_user = user or email_to_user.get(item_email)

            snapshots.append(TelemetrySnapshot(
                user=snapshot_user,
                cli_version=item.get('cli_version') or batch_cli_version,
                os=item.get('os') or batch_os,
                arch=item.get('arch') or batch_arch,
                command_executions=item.get('command_executions', {}),
                active_environment=item.get('active_environment'),
                workspace_type=item.get('workspace_type'),
                workspace_member_count=ws_counts.get(ws_id, item.get('workspace_member_count') or 0),
                project_secret_count=prj_counts.get(prj_id, item.get('project_secret_count') or 0),
                proxy_calls=item.get('proxy_calls', 0),
                proxy_blocked=item.get('proxy_blocked', 0),
                proxy_redacted=item.get('proxy_redacted', 0),
                injection_styles_used=item.get('injection_styles_used', []),
                integrations_active=item.get('integrations_active', []),
                client_timestamp=client_ts,
            ))

        await TelemetrySnapshot.objects.abulk_create(snapshots)

        # Log with attribution source for debugging
        if user:
            user_label = user.email
        elif email_to_user:
            user_label = f"{list(email_to_user.keys())[0]} (via email)"
        else:
            user_label = "anonymous"
        logger.info(f"Telemetry sync received from {user_label} ({len(snapshots)} snapshots)")

        return CustomResponse.success(
            message="Telemetry synced successfully",
            status_code=200,
            is_drf=True
        )


class PublicMetricsAPIView(APIView):
    """
    Public metrics endpoint for the AgentSecrets website and internal dashboards.
    
    Returns the full platform report:
    - Platform state: total users, projects, secrets, workspaces (from real models)
    - Engagement: active users (rolling 7d, 30d), averages
    - Growth: new signups, projects, secrets (today's delta)
    - Security: cumulative proxy stats across all time
    - Feature adoption: command usage, integrations, env distribution
    
    Uses the latest DailyMetricsAggregate if available (computed by cron).
    Falls back to live queries if no aggregate exists.
    """
    permission_classes = [AllowAny]
    serializer_class = PublicMetricsSerializer

    async def get(self, request):
        import asyncio
        from datetime import timedelta
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)

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
            self._get_today_live_metrics(today, week_ago, month_ago),
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

            # Collaboration Index (Shared / Total Workspaces)
            total_ws = platform_state['total_workspaces']
            team_collab = f"{round((platform_state['shared_workspaces'] / total_ws) * 100, 2)}%" if total_ws > 0 else "0.00%"

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
            }
            data = self._build_from_aggregate(latest, platform_state, env_dist, today_metrics, today, analytics)
        else:
            data = await self._build_live(platform_state, env_dist, os_dist)

        return CustomResponse.success(
            message="Platform metrics report",
            data=data,
            status_code=200,
            is_drf=True
        )

    async def _get_live_platform_state(self):
        return {
            'total_users': await User.objects.acount(),
            'total_projects': await Project.objects.acount(),
            'total_secrets': await Secret.objects.acount(),
            'total_workspaces': await Workspace.objects.acount(),
            'shared_workspaces': await Workspace.objects.filter(type=WorkspaceType.SHARED).acount(),
            'pending_invites': await Membership.objects.filter(status=MembershipStatus.INVITED).acount(),
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

    async def _get_today_live_metrics(self, today, week_ago, month_ago):
        import asyncio
        (
            active_counts,
            new_signups,
            new_projects,
            new_secrets
        ) = await asyncio.gather(
            User.objects.aaggregate(
                active_daily=Count('id', filter=Q(last_active_date=today)),
                active_weekly=Count('id', filter=Q(last_active_date__gte=week_ago)),
                active_monthly=Count('id', filter=Q(last_active_date__gte=month_ago))
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
        """Build response mixing live platform state and today's live activity with pre-computed heavy aggregates and analytics."""
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
            },
            'feature_adoption': {
                'environment_distribution': env_dist,
                'command_usage': agg.command_usage,
                'integration_usage': agg.integration_usage,
            },
            'report_date': str(today),
            'computed_at': timezone.now().isoformat(),
        }

    async def _build_live(self, platform_state, env_dist, os_dist):
        """Fallback: compute heavy metrics live from the database."""
        import asyncio
        from datetime import timedelta

        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)

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
                active_daily=Count('id', filter=Q(last_active_date=today)),
                active_weekly=Count('id', filter=Q(last_active_date__gte=week_ago)),
                active_monthly=Count('id', filter=Q(last_active_date__gte=month_ago))
            ),
            Project.objects.filter(secrets__isnull=False).distinct().acount(),
            Membership.objects.filter(workspace__type=WorkspaceType.SHARED, status=MembershipStatus.ACTIVE).acount(),
            User.objects.filter(created_at__date=today).acount(),
            Project.objects.filter(created_at__date=today).acount(),
            Secret.objects.filter(created_at__date=today).acount(),
            TelemetrySnapshot.objects.aaggregate(
                total_calls=Sum('proxy_calls'),
                total_blocked=Sum('proxy_blocked'),
                total_redacted=Sum('proxy_redacted')
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

        command_usage = {}
        async for snapshot in TelemetrySnapshot.objects.exclude(command_executions={}).only('command_executions'):
            for cmd, count in snapshot.command_executions.items():
                command_usage[cmd] = command_usage.get(cmd, 0) + count
        
        total_cmds = sum(command_usage.values())
        command_share = {
            k: f"{round((v / total_cmds) * 100, 2)}%" if total_cmds > 0 else "0.00%"
            for k, v in command_usage.items()
        }

        # Collaboration & adoption rates
        total_ws = platform_state['total_workspaces']
        team_collab = f"{round((platform_state['shared_workspaces'] / total_ws) * 100, 2)}%" if total_ws > 0 else "0.00%"

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
            },
            'security': {
                'total_proxy_calls': total_calls,
                'total_proxy_blocked': proxy_agg.get('total_blocked') or 0,
                'total_proxy_redacted': proxy_agg.get('total_redacted') or 0,
            },
            'feature_adoption': {
                'environment_distribution': env_dist,
                'command_usage': command_usage,
                'integration_usage': integration_usage,
            },
            'report_date': str(today),
            'computed_at': timezone.now().isoformat(),
        }


class InternalComputeMetricsAPIView(APIView):
    """
    Internal trigger for Vercel Cron to calculate daily metrics.
    
    Vercel sends CRON_SECRET via the Authorization header.
    We must bypass DRF's JWT auth entirely so it doesn't try
    to decode the cron secret as a JWT token (which causes 401).
    """
    authentication_classes = []  # No DRF auth classes
    permission_classes = [AllowAny]  # No permission checks

    def perform_authentication(self, request):
        """
        Override to completely skip DRF's authentication pipeline.
        
        Without this, DRF still runs the global DEFAULT_AUTHENTICATION_CLASSES
        which tries to decode our CRON_SECRET as a JWT and returns 401.
        """
        pass

    def _verify_cron_secret(self, request):
        """Verify the Vercel CRON_SECRET from the Authorization header."""
        import hmac
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return False
        token = auth_header[7:]  # Strip 'Bearer '
        expected = getattr(settings, 'CRON_SECRET', 'dev-secret')
        return hmac.compare_digest(token, expected)

    async def get(self, request):
        """Vercel cron calls GET by default."""
        return await self._handle_cron(request)

    async def post(self, request):
        return await self._handle_cron(request)

    async def _handle_cron(self, request):
        if not self._verify_cron_secret(request):
            return CustomResponse.error(
                message="Unauthorized cron trigger",
                status_code=401,
                is_drf=True
            )

        try:
            await sync_to_async(call_command)('calculate_metrics')
            return CustomResponse.success(message="Metrics calculated successfully", is_drf=True)
        except Exception as e:
            logger.error(f"Cron metrics calculation failed: {str(e)}")
            return CustomResponse.error(message="Metrics calculation failed", status_code=500, is_drf=True)

