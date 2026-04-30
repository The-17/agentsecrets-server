# Standard library
import logging

# Django
from django.db.models import Count, Sum, Q
from django.utils import timezone

# Third-party
from adrf.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from drf_spectacular.utils import extend_schema

# Local
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
    permission_classes = [IsAuthenticated]
    serializer_class = TelemetrySyncSerializer

    @extend_schema(exclude=True)
    async def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        await TelemetrySnapshot.objects.acreate(
            user=request.user,
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

        logger.info(f"Telemetry sync received from user {request.user.id}")

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
        # Try cached daily aggregate first
        latest = await DailyMetricsAggregate.objects.order_by('-date').afirst()

        if latest and latest.date == timezone.now().date():
            # Use pre-computed metrics from today
            metrics = {
                'total_secrets_stored': latest.total_secrets,
                'active_projects': latest.total_projects,
                'total_users': latest.total_users,
                'total_proxy_calls': latest.total_proxy_calls,
                'shared_workspaces': latest.shared_workspaces,
                'total_environments_configured': latest.environment_distribution.get('total', 0) if latest.environment_distribution else 0,
            }
        else:
            # Fall back to live queries
            total_secrets = await Secret.objects.acount()
            total_projects = await Project.objects.acount()
            total_users = await User.objects.acount()
            shared_workspaces = await Workspace.objects.filter(type=WorkspaceType.SHARED).acount()

            # Total proxy calls from all telemetry snapshots
            proxy_agg = await TelemetrySnapshot.objects.aaggregate(
                total=Sum('proxy_calls')
            )
            total_proxy_calls = proxy_agg.get('total') or 0

            # Count distinct (project, environment) pairs that have secrets
            env_count = await Secret.objects.values(
                'project', 'environment'
            ).distinct().acount()

            metrics = {
                'total_secrets_stored': total_secrets,
                'active_projects': total_projects,
                'total_users': total_users,
                'total_proxy_calls': total_proxy_calls,
                'shared_workspaces': shared_workspaces,
                'total_environments_configured': env_count,
            }

        serializer = self.serializer_class(metrics)

        return CustomResponse.success(
            message="Platform metrics retrieved",
            data=serializer.data,
            status_code=200
        )
