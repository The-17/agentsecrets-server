import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Sum, Count, Q

from apps.accounts.models import User
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import Workspace, WorkspaceType
from apps.telemetry.models import TelemetrySnapshot, DailyMetricsAggregate

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Aggregates telemetry snapshots into daily metrics'

    def handle(self, *args, **options):
        today = timezone.now().date()
        self.stdout.write(f"Calculating metrics for {today}...")

        # 1. Basic Platform Counts & Signups
        total_users = User.objects.count()
        new_signups = User.objects.filter(created_at__date=today).count()
        
        total_projects = Project.objects.count()
        new_projects = Project.objects.filter(created_at__date=today).count()
        
        total_secrets = Secret.objects.count()
        new_secrets = Secret.objects.filter(created_at__date=today).count()
        
        total_workspaces = Workspace.objects.count()
        shared_workspaces = Workspace.objects.filter(type=WorkspaceType.SHARED).count()
        
        from apps.workspaces.models import Membership, MembershipStatus
        total_invites = Membership.objects.filter(status=MembershipStatus.INVITED).count()

        # 2. Activity Metrics (Daily, Weekly, Monthly)
        snapshots_today = TelemetrySnapshot.objects.filter(created_at__date=today)
        active_users_daily = snapshots_today.values('user').distinct().count()
        
        # Rolling Active Users
        week_ago = today - timezone.timedelta(days=7)
        month_ago = today - timezone.timedelta(days=30)
        
        active_users_weekly = TelemetrySnapshot.objects.filter(
            created_at__date__gte=week_ago
        ).values('user').distinct().count()
        
        active_users_monthly = TelemetrySnapshot.objects.filter(
            created_at__date__gte=month_ago
        ).values('user').distinct().count()
        
        # 3. Platform Averages (Rounded)
        avg_secrets_per_project = round(total_secrets / total_projects) if total_projects > 0 else 0
        avg_projects_per_workspace = round(total_projects / total_workspaces) if total_workspaces > 0 else 0
        
        # Avg members per shared workspace
        total_memberships = Membership.objects.filter(workspace__type=WorkspaceType.SHARED).count()
        avg_members_per_workspace = round(total_memberships / shared_workspaces) if shared_workspaces > 0 else 1

        # 4. Proxy Stats
        proxy_stats = snapshots_today.aggregate(
            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted')
        )

        # 5. Aggregate Command Usage
        command_usage = {}
        for snapshot in snapshots_today:
            for cmd, count in snapshot.command_executions.items():
                command_usage[cmd] = command_usage.get(cmd, 0) + count

        # 6. Environment Distribution
        env_dist = {
            'development': snapshots_today.filter(active_environment='development').count(),
            'staging': snapshots_today.filter(active_environment='staging').count(),
            'production': snapshots_today.filter(active_environment='production').count(),
        }

        # 7. Integration Usage
        integration_usage = {}
        for snapshot in snapshots_today:
            for integration in snapshot.integrations_active:
                integration_usage[integration] = integration_usage.get(integration, 0) + 1

        # Save or Update Aggregate
        aggregate, created = DailyMetricsAggregate.objects.update_or_create(
            date=today,
            defaults={
                'total_users': total_users,
                'active_users_daily': active_users_daily,
                'active_users_weekly': active_users_weekly,
                'active_users_monthly': active_users_monthly,
                'new_signups': new_signups,
                'total_projects': total_projects,
                'new_projects': new_projects,
                'total_secrets': total_secrets,
                'new_secrets': new_secrets,
                'total_workspaces': total_workspaces,
                'shared_workspaces': shared_workspaces,
                'total_invites': total_invites,
                'total_proxy_calls': proxy_stats['total_calls'] or 0,
                'total_proxy_blocked': proxy_stats['total_blocked'] or 0,
                'total_proxy_redacted': proxy_stats['total_redacted'] or 0,
                'avg_secrets_per_project': avg_secrets_per_project,
                'avg_projects_per_workspace': avg_projects_per_workspace,
                'avg_members_per_workspace': avg_members_per_workspace,
                'command_usage': command_usage,
                'environment_distribution': env_dist,
                'integration_usage': integration_usage,
            }
        )

        self.stdout.write(self.style.SUCCESS(f"Successfully calculated metrics for {today}"))
