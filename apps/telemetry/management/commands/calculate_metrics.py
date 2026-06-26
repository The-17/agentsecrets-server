import logging
from datetime import timedelta, datetime
from django.core.management.base import BaseCommand
from django.db.models import Sum, Count, Avg, Q, F
from django.utils import timezone

from apps.accounts.models import User
from apps.secrets_app.models import Project, Secret
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipStatus
from apps.telemetry.models import TelemetrySnapshot, DailyMetricsAggregate

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Calculates historically accurate platform metrics with temporal pinning'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Calculate metrics for a specific date (YYYY-MM-DD)',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to look back for rolling refresh (default 7)',
        )

    def handle(self, *args, **options):
        from django.db import connections
        if options['date']:
            target_dates = [datetime.strptime(options['date'], '%Y-%m-%d').date()]
        else:
            # Production mode: Recalculate a rolling window to account for late telemetry syncs.
            # This ensures forensic accuracy even if users are offline for a few days.
            anchor_date = (timezone.now() - timedelta(hours=2)).date()
            days_to_refresh = options['days']
            target_dates = [anchor_date - timedelta(days=i) for i in range(days_to_refresh)]
            target_dates.reverse() # Process oldest to newest for logical consistency

        try:
            for date in target_dates:
                self.calculate_for_date(date)
        finally:
            # Ensure connections are closed to prevent leaks in serverless/pooled environments
            connections.close_all()

    def calculate_for_date(self, target_date):
        week_ago = target_date - timedelta(days=7)
        month_ago = target_date - timedelta(days=30)

        self.stdout.write(f"Refining platform metrics for {target_date}...")

        # ──────────────────────────────────────────────
        # 1. PLATFORM STATE — PINNED TO TARGET DATE
        #    These counts reflect the state as it was at the end of target_date.
        # ──────────────────────────────────────────────
        total_users = User.objects.filter(created_at__date__lte=target_date).count()
        total_projects = Project.objects.filter(created_at__date__lte=target_date).count()
        total_secrets = Secret.objects.filter(created_at__date__lte=target_date).count()
        total_workspaces = Workspace.objects.filter(created_at__date__lte=target_date).count()
        shared_workspaces = Workspace.objects.filter(
            type=WorkspaceType.SHARED, 
            created_at__date__lte=target_date
        ).count()

        # Count active policies: secrets with a non-empty policy dict + agents with
        # a non-empty capabilities dict, both pinned to target_date.
        from apps.workspaces.models import AgentRegistration
        secret_policies = (
            Secret.objects
            .filter(created_at__date__lte=target_date)
            .exclude(policy__isnull=True)
            .exclude(policy__exact={})
            .count()
        )
        agent_policies = (
            AgentRegistration.objects
            .filter(created_at__date__lte=target_date)
            .exclude(capabilities__isnull=True)
            .exclude(capabilities__exact={})
            .count()
        )
        total_policies = secret_policies + agent_policies

        # ──────────────────────────────────────────────
        # 2. GROWTH — GROWTH ON SPECIFIC DATE
        # ──────────────────────────────────────────────
        new_signups = User.objects.filter(created_at__date=target_date).count()
        new_projects = Project.objects.filter(created_at__date=target_date).count()
        new_secrets = Secret.objects.filter(created_at__date=target_date).count()

        # ──────────────────────────────────────────────
        # 3. ENGAGEMENT — ROLLING ACTIVE USERS
        #    Prioritizes client_timestamp for accurate back-dating of offline activity.
        # ──────────────────────────────────────────────
        active_users_daily = (
            User.objects
            .filter(last_active_at__date=target_date)
            .count()
        )
        active_users_weekly = (
            User.objects
            .filter(last_active_at__date__range=[week_ago, target_date])
            .count()
        )
        active_users_monthly = (
            User.objects
            .filter(last_active_at__date__range=[month_ago, target_date])
            .count()
        )

        # ──────────────────────────────────────────────
        # 4. COLLABORATION — WORKSPACE HEALTH
        # ──────────────────────────────────────────────
        total_invites = Membership.objects.filter(
            status=MembershipStatus.INVITED,
            created_at__date__lte=target_date
        ).count()

        if shared_workspaces > 0:
            active_memberships_in_shared = (
                Membership.objects
                .filter(
                    workspace__type=WorkspaceType.SHARED,
                    status=MembershipStatus.ACTIVE,
                    created_at__date__lte=target_date
                )
                .count()
            )
            avg_members_per_workspace = round(active_memberships_in_shared / shared_workspaces, 1)
        else:
            avg_members_per_workspace = 0.0

        projects_with_secrets = (
            Project.objects
            .filter(secrets__isnull=False, created_at__date__lte=target_date)
            .distinct()
            .count()
        )
        if projects_with_secrets > 0:
            avg_secrets_per_project = round(total_secrets / projects_with_secrets, 1)
        else:
            avg_secrets_per_project = 0.0

        if total_workspaces > 0:
            avg_projects_per_workspace = round(total_projects / total_workspaces, 1)
        else:
            avg_projects_per_workspace = 0.0

        # ──────────────────────────────────────────────
        # 5. PROXY & SECURITY — CUMULATIVE UP TO TARGET DATE
        # ──────────────────────────────────────────────
        proxy_stats = TelemetrySnapshot.objects.filter(
            Q(client_timestamp__date__lte=target_date) | 
            Q(client_timestamp__isnull=True, created_at__date__lte=target_date)
        ).aggregate(
            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted'),
            # v3 Core
            total_secrets_resolved=Sum('secrets_resolved'),
            total_proxy_duration_ms=Sum('total_proxy_duration_ms'),
            # Execution Paths
            total_proxy_calls_daemon=Sum('proxy_calls_daemon'),
            total_proxy_calls_transient=Sum('proxy_calls_transient'),
            total_proxy_calls_mcp=Sum('proxy_calls_mcp'),
            total_proxy_calls_direct=Sum('proxy_calls_direct'),
            total_developer_commands=Sum('developer_commands'),
            # Shielding
            total_ssrf_blocked=Sum('ssrf_attempts_blocked'),
            total_allowlist_violations=Sum('allowlist_violations'),
            total_redactions_performed=Sum('response_redactions'),
            total_process_verifications_failed=Sum('process_verifications_failed'),
            total_production_write_challenges=Sum('production_write_challenges'),
            # Latency Averages
            avg_keychain_resolution_ms=Avg('keychain_resolution_ms'),
            avg_session_refresh_ms=Avg('session_refresh_ms'),
            # Onboarding
            total_interactive_prompts_shown=Sum('interactive_prompts_shown'),
            total_interactive_prompts_skipped=Sum('interactive_prompts_skipped'),
            total_drift_diffs_detected=Sum('drift_diffs_detected'),
            # Integrity
            total_log_verifications=Sum('log_chain_verifications'),
            total_tampering_alerts=Sum('tampering_detected'),
            # Node Metadata (Boolean flag aggregation)
            total_headless_nodes=Count('id', filter=Q(is_headless_node=True)),
            total_active_keychains=Count('id', filter=Q(keychain_initialized=True)),
            # Identity & Capabilities
            total_identity_anonymous_calls=Sum('identity_anonymous_calls'),
            total_identity_declared_calls=Sum('identity_declared_calls'),
            total_identity_issued_calls=Sum('identity_issued_calls'),
            total_capability_violations_blocked=Sum('capability_violations_blocked'),
            total_process_verifications_passed=Sum('process_verifications_passed'),
            # Errors
            total_errors_auth=Sum('errors_auth_count'),
            total_errors_keychain=Sum('errors_keychain_count'),
            total_errors_secrets=Sum('errors_secrets_count'),
            total_errors_network=Sum('errors_network_count'),
            total_errors_system=Sum('errors_system_count'),
            total_errors_unknown=Sum('errors_unknown_count'),
        )

        # ──────────────────────────────────────────────
        # 6. COMMAND USAGE — CUMULATIVE UP TO TARGET DATE
        # ──────────────────────────────────────────────
        VALID_COMMANDS = {
            'root', 'init', 'login', 'logout', 'status', 'workspace', 'project',
            'secrets', 'agent', 'log', 'proxy', 'mcp', 'call', 'environment',
            'env', 'exec', 'docs', '-h', '-v', '--help', '--version'
        }
        command_usage = {}
        typos_usage = {}
        relevant_snapshots = (
            TelemetrySnapshot.objects
            .filter(
                Q(client_timestamp__date__lte=target_date) | 
                Q(client_timestamp__isnull=True, created_at__date__lte=target_date)
            )
            .exclude(command_executions={})
            .only('command_executions')
        )
        for snapshot in relevant_snapshots:
            for cmd, count in snapshot.command_executions.items():
                if cmd in VALID_COMMANDS:
                    command_usage[cmd] = command_usage.get(cmd, 0) + count
                else:
                    typos_usage[cmd] = typos_usage.get(cmd, 0) + count

        # ──────────────────────────────────────────────
        # 7. ENVIRONMENT DISTRIBUTION — PINNED STATE
        # ──────────────────────────────────────────────
        env_dist = {
            'development': Secret.objects.filter(environment='development', created_at__date__lte=target_date).count(),
            'staging': Secret.objects.filter(environment='staging', created_at__date__lte=target_date).count(),
            'production': Secret.objects.filter(environment='production', created_at__date__lte=target_date).count(),
        }

        # ──────────────────────────────────────────────
        # 8. INTEGRATION USAGE — CUMULATIVE ADOPTION
        # ──────────────────────────────────────────────
        integration_usage = {}
        integration_snapshots = (
            TelemetrySnapshot.objects
            .filter(
                Q(client_timestamp__date__lte=target_date) | 
                Q(client_timestamp__isnull=True, created_at__date__lte=target_date)
            )
            .exclude(integrations_active=[])
            .only('integrations_active')
        )
        for snapshot in integration_snapshots:
            for integration in snapshot.integrations_active:
                integration_usage[integration] = integration_usage.get(integration, 0) + 1

        # ──────────────────────────────────────────────
        # 9. SAVE — ATOMIC UPDATE
        # ──────────────────────────────────────────────
        DailyMetricsAggregate.objects.update_or_create(
            date=target_date,
            defaults={
                'total_users': total_users,
                'active_users_daily': active_users_daily,
                'active_users_weekly': active_users_weekly,
                'active_users_monthly': active_users_monthly,
                'new_signups': new_signups,
                'total_projects': total_projects,
                'total_secrets': total_secrets,
                'new_projects': new_projects,
                'new_secrets': new_secrets,
                'total_workspaces': total_workspaces,
                'shared_workspaces': shared_workspaces,
                'total_invites': total_invites,
                'avg_members_per_workspace': avg_members_per_workspace,
                'avg_secrets_per_project': avg_secrets_per_project,
                'avg_projects_per_workspace': avg_projects_per_workspace,
                'total_policies': total_policies,
                'total_proxy_calls': proxy_stats['total_calls'] or 0,
                'total_proxy_blocked': proxy_stats['total_blocked'] or 0,
                'total_proxy_redacted': proxy_stats['total_redacted'] or 0,
                'command_usage': command_usage,
                'environment_distribution': env_dist,
                'integration_usage': integration_usage,
                'total_secrets_resolved': proxy_stats['total_secrets_resolved'] or 0,
                'total_proxy_duration_ms': proxy_stats['total_proxy_duration_ms'] or 0,
                'total_proxy_calls_daemon': proxy_stats['total_proxy_calls_daemon'] or 0,
                'total_proxy_calls_transient': proxy_stats['total_proxy_calls_transient'] or 0,
                'total_proxy_calls_mcp': proxy_stats['total_proxy_calls_mcp'] or 0,
                'total_proxy_calls_direct': proxy_stats['total_proxy_calls_direct'] or 0,
                'total_developer_commands': proxy_stats['total_developer_commands'] or 0,
                'total_ssrf_blocked': proxy_stats['total_ssrf_blocked'] or 0,
                'total_allowlist_violations': proxy_stats['total_allowlist_violations'] or 0,
                'total_redactions_performed': proxy_stats['total_redactions_performed'] or 0,
                'total_process_verifications_failed': proxy_stats['total_process_verifications_failed'] or 0,
                'total_production_write_challenges': proxy_stats['total_production_write_challenges'] or 0,
                'avg_keychain_resolution_ms': proxy_stats['avg_keychain_resolution_ms'] or 0.0,
                'avg_session_refresh_ms': proxy_stats['avg_session_refresh_ms'] or 0.0,
                'total_interactive_prompts_shown': proxy_stats['total_interactive_prompts_shown'] or 0,
                'total_interactive_prompts_skipped': proxy_stats['total_interactive_prompts_skipped'] or 0,
                'total_drift_diffs_detected': proxy_stats['total_drift_diffs_detected'] or 0,
                'total_log_verifications': proxy_stats['total_log_verifications'] or 0,
                'total_tampering_alerts': proxy_stats['total_tampering_alerts'] or 0,
                'total_headless_nodes': proxy_stats['total_headless_nodes'] or 0,
                'total_active_keychains': proxy_stats['total_active_keychains'] or 0,
                'total_identity_anonymous_calls': proxy_stats['total_identity_anonymous_calls'] or 0,
                'total_identity_declared_calls': proxy_stats['total_identity_declared_calls'] or 0,
                'total_identity_issued_calls': proxy_stats['total_identity_issued_calls'] or 0,
                'total_capability_violations_blocked': proxy_stats['total_capability_violations_blocked'] or 0,
                'total_process_verifications_passed': proxy_stats['total_process_verifications_passed'] or 0,
                'total_errors_auth': proxy_stats['total_errors_auth'] or 0,
                'total_errors_keychain': proxy_stats['total_errors_keychain'] or 0,
                'total_errors_secrets': proxy_stats['total_errors_secrets'] or 0,
                'total_errors_network': proxy_stats['total_errors_network'] or 0,
                'total_errors_system': proxy_stats['total_errors_system'] or 0,
                'total_errors_unknown': proxy_stats['total_errors_unknown'] or 0,
                'typos_usage': typos_usage,
            }
        )
