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
from drf_spectacular.utils import extend_schema

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

    @extend_schema(exclude=True)
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

            snapshots.append(TelemetrySnapshot(
                user=user,
                cli_version=item.get('cli_version'),
                os=item.get('os'),
                arch=item.get('arch'),
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

        user_id = request.user.id if request.user.is_authenticated else "anonymous"
        logger.info(f"Telemetry sync received from user {user_id} ({len(snapshots)} snapshots)")

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

    @extend_schema(exclude=True)
    async def get(self, request):
        # 1. ALWAYS get live platform state (super fast queries)
        # This guarantees the dashboard never shows stale core counts.
        platform_state = await self._get_live_platform_state()
        env_dist = await self._get_live_env_distribution()

        # 2. Get heavy metrics (engagement, cumulative stats) from the daily aggregate
        latest = await DailyMetricsAggregate.objects.order_by('-date').afirst()

        if latest:
            data = self._build_from_aggregate(latest, platform_state, env_dist)
        else:
            data = await self._build_live(platform_state, env_dist)

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

    def _build_from_aggregate(self, agg, platform_state, env_dist):
        """Build response mixing live platform state with pre-computed heavy aggregates."""
        return {
            'platform': platform_state,
            'engagement': {
                'active_users_daily': agg.active_users_daily,
                'active_users_weekly': agg.active_users_weekly,
                'active_users_monthly': agg.active_users_monthly,
                'avg_secrets_per_project': agg.avg_secrets_per_project,
                'avg_projects_per_workspace': agg.avg_projects_per_workspace,
                'avg_members_per_shared_workspace': agg.avg_members_per_workspace,
            },
            'growth': {
                'new_signups_today': agg.new_signups,
                'new_projects_today': agg.new_projects,
                'new_secrets_today': agg.new_secrets,
            },
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
            'report_date': str(agg.date),
            'computed_at': agg.computed_at.isoformat() if agg.computed_at else None,
        }

    async def _build_live(self, platform_state, env_dist):
        """Fallback: compute heavy metrics live from the database."""
        from datetime import timedelta

        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)

        # Engagement — rolling active users from telemetry
        active_daily = await (
            TelemetrySnapshot.objects
            .filter(created_at__date=today, user__isnull=False)
            .values('user').distinct().acount()
        )
        active_weekly = await (
            TelemetrySnapshot.objects
            .filter(created_at__date__gte=week_ago, user__isnull=False)
            .values('user').distinct().acount()
        )
        active_monthly = await (
            TelemetrySnapshot.objects
            .filter(created_at__date__gte=month_ago, user__isnull=False)
            .values('user').distinct().acount()
        )

        # Averages
        projects_with_secrets = await Project.objects.filter(secrets__isnull=False).distinct().acount()
        avg_spp = round(platform_state['total_secrets'] / projects_with_secrets, 1) if projects_with_secrets > 0 else 0.0
        avg_ppw = round(platform_state['total_projects'] / platform_state['total_workspaces'], 1) if platform_state['total_workspaces'] > 0 else 0.0

        if platform_state['shared_workspaces'] > 0:
            active_shared_memberships = await (
                Membership.objects
                .filter(workspace__type=WorkspaceType.SHARED, status=MembershipStatus.ACTIVE)
                .acount()
            )
            avg_mpw = round(active_shared_memberships / platform_state['shared_workspaces'], 1)
        else:
            avg_mpw = 0.0

        # Growth
        new_signups = await User.objects.filter(created_at__date=today).acount()
        new_projects = await Project.objects.filter(created_at__date=today).acount()
        new_secrets = await Secret.objects.filter(created_at__date=today).acount()

        # Security — cumulative proxy stats across ALL telemetry
        proxy_agg = await TelemetrySnapshot.objects.aaggregate(
            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted')
        )

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
            'security': {
                'total_proxy_calls': proxy_agg.get('total_calls') or 0,
                'total_proxy_blocked': proxy_agg.get('total_blocked') or 0,
                'total_proxy_redacted': proxy_agg.get('total_redacted') or 0,
            },
            'feature_adoption': {
                'environment_distribution': env_dist,
                'command_usage': {},
                'integration_usage': {},
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

    @extend_schema(exclude=True)
    async def get(self, request):
        """Vercel cron calls GET by default."""
        return await self._handle_cron(request)

    @extend_schema(exclude=True)
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

