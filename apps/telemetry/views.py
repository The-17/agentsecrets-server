# Standard library
import logging

# Django
from django.db.models import Count, Sum, Q
from django.utils import timezone

# Third-party
from adrf.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
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


class TelemetrySyncAPIView(APIView):
    """
    Receive batched CLI telemetry data.
    
    The CLI collects telemetry locally and syncs every 24 hours.
    This endpoint stores the payload for aggregation and analysis.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle, UserRateThrottle]
    serializer_class = TelemetrySyncSerializer

    @extend_schema(exclude=True)
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        
        user = request.user if request.user.is_authenticated else None

        await TelemetrySnapshot.objects.acreate(
            user=user,
            cli_version=data.get('cli_version'),
            os=data.get('os'),
            arch=data.get('arch'),
            command_executions=data.get('command_executions', {}),
            active_environment=data.get('active_environment'),
            workspace_type=data.get('workspace_type'),
            workspace_member_count=data.get('workspace_member_count'),
            project_secret_count=data.get('project_secret_count'),
            proxy_calls=data.get('proxy_calls', 0),
            proxy_blocked=data.get('proxy_blocked', 0),
            proxy_redacted=data.get('proxy_redacted', 0),
            injection_styles_used=data.get('injection_styles_used', []),
            integrations_active=data.get('integrations_active', []),
            client_timestamp=data.get('timestamp'),
        )

        user_id = request.user.id if request.user.is_authenticated else "anonymous"
        logger.info(f"Telemetry sync received from user {user_id}")

        return CustomResponse.success(
            message="Telemetry synced successfully",
            status_code=200
        )


class PublicMetricsAPIView(APIView):
    """
    Public metrics endpoint for the AgentSecrets website.
    
    Returns aggregate platform stats. No authentication required.
    No sensitive data is exposed — only aggregate counts.
    
    Tries to use the latest DailyMetricsAggregate for performance.
    Falls back to live database queries if no aggregate exists.
    """
    permission_classes = [AllowAny]
    serializer_class = PublicMetricsSerializer

    @extend_schema(exclude=True)
    async def get(self, request):
        """
        Get the cumulative platform metrics report.
        
        This returns the lifetime state of the product (totals, averages, and rolling retention)
        rather than a single day's snapshot.
        """
        # Try to get the latest aggregate for the current totals and engagement metrics
        latest = await DailyMetricsAggregate.objects.order_by('-date').afirst()
        
        # Calculate cumulative proxy calls across all time
        proxy_agg = await TelemetrySnapshot.objects.aaggregate(
            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted')
        )

        if latest:
            # Use pre-computed totals from the latest aggregate
            data = {
                'total_users': latest.total_users,
                'total_projects': latest.total_projects,
                'total_secrets': latest.total_secrets,
                'total_workspaces': latest.total_workspaces,
                'shared_workspaces': latest.shared_workspaces,
                'total_proxy_calls': proxy_agg.get('total_calls') or 0,
                'total_proxy_blocked': proxy_agg.get('total_blocked') or 0,
                'total_proxy_redacted': proxy_agg.get('total_redacted') or 0,
                'active_users_weekly': latest.active_users_weekly,
                'active_users_monthly': latest.active_users_monthly,
                'avg_secrets_per_project': latest.avg_secrets_per_project,
                'avg_projects_per_workspace': latest.avg_projects_per_workspace,
                'avg_members_per_workspace': latest.avg_members_per_workspace,
                'command_usage_all_time': latest.command_usage,  # Today's command usage as a proxy for trend
                'environment_distribution': latest.environment_distribution,
                'integration_usage': latest.integration_usage,
                'report_generated_at': latest.computed_at
            }
        else:
            # Fall back to live queries if no aggregates exist yet
            total_users = await User.objects.acount()
            total_projects = await Project.objects.acount()
            total_secrets = await Secret.objects.acount()
            total_workspaces = await Workspace.objects.acount()
            shared_workspaces = await Workspace.objects.filter(type=WorkspaceType.SHARED).acount()

            data = {
                'total_users': total_users,
                'total_projects': total_projects,
                'total_secrets': total_secrets,
                'total_workspaces': total_workspaces,
                'shared_workspaces': shared_workspaces,
                'total_proxy_calls': proxy_agg.get('total_calls') or 0,
                'total_proxy_blocked': proxy_agg.get('total_blocked') or 0,
                'total_proxy_redacted': proxy_agg.get('total_redacted') or 0,
                'avg_secrets_per_project': round(total_secrets / total_projects) if total_projects > 0 else 0,
                'avg_projects_per_workspace': round(total_projects / total_workspaces) if total_workspaces > 0 else 0,
                'report_generated_at': timezone.now()
            }

        return CustomResponse.success(
            message="Cumulative platform report retrieved",
            data=data,
            status_code=200
        )


class InternalComputeMetricsAPIView(APIView):
    """
    Internal trigger for Vercel Cron to calculate daily metrics.
    
    Expects a CRON_SECRET header for security.
    """
    authentication_classes = []  # Disable JWT auth so we can use manual secret check
    permission_classes = [AllowAny]

    @extend_schema(exclude=True)
    async def post(self, request):
        cron_secret = request.headers.get('Authorization')
        expected_secret = f"Bearer {getattr(settings, 'CRON_SECRET', 'dev-secret')}"
        
        if cron_secret != expected_secret:
            return CustomResponse.error(
                message="Unauthorized cron trigger",
                status_code=401
            )

        # Run the management command in a separate thread to avoid blocking the async loop
        # and to satisfy Django's sync-only database safety checks.
        try:
            await sync_to_async(call_command)('calculate_metrics')
            return CustomResponse.success(message="Metrics calculated successfully")
        except Exception as e:
            logger.error(f"Cron metrics calculation failed: {str(e)}")
            return CustomResponse.error(message="Metrics calculation failed", status_code=500)

