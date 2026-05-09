import logging
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Sum, Count, Avg, Q, F
from django.utils import timezone

from apps.accounts.models import User
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipStatus
from apps.telemetry.models import TelemetrySnapshot, DailyMetricsAggregate

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Calculates accurate platform metrics from the actual database state'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Calculate metrics for a specific date (YYYY-MM-DD)',
        )

    def handle(self, *args, **options):
        if options['date']:
            from datetime import datetime
            today = datetime.strptime(options['date'], '%Y-%m-%d').date()
        else:
            # If the cron runs slightly after midnight (e.g., 00:19), subtract 2 hours
            # so we still calculate for the intended day.
            today = (timezone.now() - timedelta(hours=2)).date()
            
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)

        self.stdout.write(f"Calculating platform metrics for {today}...")

        # ──────────────────────────────────────────────
        # 1. PLATFORM STATE — direct from source models
        #    These are the ground truth, not telemetry
        # ──────────────────────────────────────────────
        total_users = User.objects.count()
        total_projects = Project.objects.count()
        total_secrets = Secret.objects.count()
        total_workspaces = Workspace.objects.count()
        shared_workspaces = Workspace.objects.filter(type=WorkspaceType.SHARED).count()

        # ──────────────────────────────────────────────
        # 2. GROWTH — how fast are we growing?
        # ──────────────────────────────────────────────
        new_signups = User.objects.filter(created_at__date=today).count()
        new_projects = Project.objects.filter(created_at__date=today).count()
        new_secrets = Secret.objects.filter(created_at__date=today).count()

        # ──────────────────────────────────────────────
        # 3. ENGAGEMENT — rolling active users from telemetry
        #    A user is "active" if they sent at least one telemetry
        #    sync in the window. This undercounts (syncs every 24h),
        #    but it's the most honest signal we have.
        # ──────────────────────────────────────────────
        active_users_daily = (
            TelemetrySnapshot.objects
            .filter(created_at__date=today, user__isnull=False)
            .values('user')
            .distinct()
            .count()
        )
        active_users_weekly = (
            TelemetrySnapshot.objects
            .filter(created_at__date__gte=week_ago, user__isnull=False)
            .values('user')
            .distinct()
            .count()
        )
        active_users_monthly = (
            TelemetrySnapshot.objects
            .filter(created_at__date__gte=month_ago, user__isnull=False)
            .values('user')
            .distinct()
            .count()
        )

        # ──────────────────────────────────────────────
        # 4. COLLABORATION — workspace health
        # ──────────────────────────────────────────────
        total_invites = Membership.objects.filter(status=MembershipStatus.INVITED).count()

        # Average members per SHARED workspace (personal always = 1, that's noise)
        if shared_workspaces > 0:
            active_memberships_in_shared = (
                Membership.objects
                .filter(
                    workspace__type=WorkspaceType.SHARED,
                    status=MembershipStatus.ACTIVE
                )
                .count()
            )
            avg_members_per_workspace = round(active_memberships_in_shared / shared_workspaces, 1)
        else:
            avg_members_per_workspace = 0.0

        # Average secrets per project (only projects that HAVE secrets)
        projects_with_secrets = Project.objects.filter(secrets__isnull=False).distinct().count()
        if projects_with_secrets > 0:
            avg_secrets_per_project = round(total_secrets / projects_with_secrets, 1)
        else:
            avg_secrets_per_project = 0.0

        # Average projects per workspace
        if total_workspaces > 0:
            avg_projects_per_workspace = round(total_projects / total_workspaces, 1)
        else:
            avg_projects_per_workspace = 0.0

        # ──────────────────────────────────────────────
        # 5. PROXY & SECURITY — CUMULATIVE across ALL telemetry
        #    Not just today. These are lifetime platform totals.
        # ──────────────────────────────────────────────
        proxy_stats = TelemetrySnapshot.objects.aggregate(
            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted')
        )

        # ──────────────────────────────────────────────
        # 6. COMMAND USAGE — CUMULATIVE across ALL telemetry
        #    Shows which features are actually being used.
        # ──────────────────────────────────────────────
        command_usage = {}
        for snapshot in TelemetrySnapshot.objects.exclude(command_executions={}).only('command_executions'):
            for cmd, count in snapshot.command_executions.items():
                command_usage[cmd] = command_usage.get(cmd, 0) + count

        # ──────────────────────────────────────────────
        # 7. ENVIRONMENT DISTRIBUTION — from actual secrets
        #    This is the real platform state, not CLI telemetry.
        # ──────────────────────────────────────────────
        env_dist = {
            'development': Secret.objects.filter(environment='development').count(),
            'staging': Secret.objects.filter(environment='staging').count(),
            'production': Secret.objects.filter(environment='production').count(),
        }

        # ──────────────────────────────────────────────
        # 8. INTEGRATION USAGE — CUMULATIVE across ALL telemetry
        #    Shows which integration methods users have adopted.
        # ──────────────────────────────────────────────
        integration_usage = {}
        for snapshot in (
            TelemetrySnapshot.objects
            .exclude(integrations_active=[])
            .only('integrations_active')
        ):
            for integration in snapshot.integrations_active:
                integration_usage[integration] = integration_usage.get(integration, 0) + 1

        # ──────────────────────────────────────────────
        # SAVE — update_or_create so re-runs are safe
        # ──────────────────────────────────────────────
        aggregate, created = DailyMetricsAggregate.objects.update_or_create(
            date=today,
            defaults={
                # Platform state
                'total_users': total_users,
                'total_projects': total_projects,
                'total_secrets': total_secrets,
                'total_workspaces': total_workspaces,
                'shared_workspaces': shared_workspaces,

                # Growth (today)
                'new_signups': new_signups,
                'new_projects': new_projects,
                'new_secrets': new_secrets,

                # Engagement (rolling windows)
                'active_users_daily': active_users_daily,
                'active_users_weekly': active_users_weekly,
                'active_users_monthly': active_users_monthly,

                # Collaboration
                'total_invites': total_invites,
                'avg_members_per_workspace': avg_members_per_workspace,
                'avg_secrets_per_project': avg_secrets_per_project,
                'avg_projects_per_workspace': avg_projects_per_workspace,

                # Proxy & Security (cumulative, all time)
                'total_proxy_calls': proxy_stats['total_calls'] or 0,
                'total_proxy_blocked': proxy_stats['total_blocked'] or 0,
                'total_proxy_redacted': proxy_stats['total_redacted'] or 0,

                # Feature usage (cumulative, all time)
                'command_usage': command_usage,
                'environment_distribution': env_dist,
                'integration_usage': integration_usage,
            }
        )

        action = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(
            f"{action} metrics for {today}: "
            f"{total_users} users, {total_secrets} secrets, "
            f"{total_projects} projects, {shared_workspaces} shared workspaces, "
            f"env dist: {env_dist}"
        ))
