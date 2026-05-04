# Django
from django.db import models

# Local
from apps.common.models import BaseModel
from apps.accounts.models import User


class TelemetrySnapshot(BaseModel):
    """
    Stores each CLI telemetry sync payload.
    
    The CLI batches telemetry locally and syncs every 24 hours.
    Each snapshot captures command usage, proxy metrics, and
    client environment info for one sync period.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='telemetry_snapshots',
        null=True, blank=True,
        help_text="The user who sent this telemetry (null if anonymous)"
    )

    # CLI environment
    cli_version = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="CLI version string (e.g. 0.4.2)"
    )
    os = models.CharField(
        max_length=50, null=True, blank=True,
        help_text="Operating system (e.g. darwin, linux, windows)"
    )
    arch = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="Architecture (e.g. arm64, amd64)"
    )

    # Command usage
    command_executions = models.JSONField(
        default=dict,
        help_text="Map of command name to execution count for this sync period"
    )

    # Workspace context (anonymized — no names, just types and counts)
    active_environment = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="Active environment at sync time (development/staging/production)"
    )
    workspace_type = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="Type of active workspace (personal/shared)"
    )
    workspace_member_count = models.IntegerField(
        null=True, blank=True,
        help_text="Number of members in the active workspace"
    )
    project_secret_count = models.IntegerField(
        null=True, blank=True,
        help_text="Number of secrets in the active project"
    )

    # Proxy metrics (computed locally by the CLI)
    proxy_calls = models.IntegerField(
        default=0,
        help_text="Total proxy credential injection calls in this period"
    )
    proxy_blocked = models.IntegerField(
        default=0,
        help_text="Proxy calls blocked by allowlist in this period"
    )
    proxy_redacted = models.IntegerField(
        default=0,
        help_text="Proxy responses where credentials were redacted"
    )

    # Injection style distribution
    injection_styles_used = models.JSONField(
        default=list, blank=True,
        help_text="List of injection styles used (bearer, header, query, basic, body_field, form_field)"
    )

    # Integrations
    integrations_active = models.JSONField(
        default=list, blank=True,
        help_text="List of active integrations (mcp, openclaw, env, proxy, sdk)"
    )

    # Original client timestamp
    client_timestamp = models.DateTimeField(
        null=True, blank=True,
        help_text="Timestamp from the CLI when telemetry was generated"
    )

    def __str__(self):
        user_display = self.user.email if self.user else "Anonymous"
        return f"{user_display} - {self.created_at:%Y-%m-%d %H:%M}"

    class Meta:
        db_table = 'telemetry_snapshots'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['-created_at']),
        ]


class DailyMetricsAggregate(models.Model):
    """
    Pre-computed daily aggregate metrics.
    
    Populated by a management command or periodic task.
    Powers the public metrics endpoint and internal dashboards.
    """
    date = models.DateField(unique=True)

    # User metrics
    total_users = models.IntegerField(default=0)
    active_users_daily = models.IntegerField(default=0)
    active_users_weekly = models.IntegerField(default=0)
    active_users_monthly = models.IntegerField(default=0)
    new_signups = models.IntegerField(default=0)

    # Project & secret metrics
    total_projects = models.IntegerField(default=0)
    total_secrets = models.IntegerField(default=0)
    new_projects = models.IntegerField(default=0)
    new_secrets = models.IntegerField(default=0)

    # Workspace metrics
    total_workspaces = models.IntegerField(default=0)
    shared_workspaces = models.IntegerField(default=0)
    total_invites = models.IntegerField(default=0)
    avg_members_per_workspace = models.FloatField(default=0.0)
    avg_secrets_per_project = models.FloatField(default=0.0)
    avg_projects_per_workspace = models.FloatField(default=0.0)

    # Proxy & security metrics (aggregated from telemetry snapshots)
    total_proxy_calls = models.IntegerField(default=0)
    total_proxy_blocked = models.IntegerField(default=0)
    total_proxy_redacted = models.IntegerField(default=0)

    # Command usage aggregate
    command_usage = models.JSONField(
        default=dict,
        help_text="Aggregated command usage across all users for this day"
    )

    # Environment distribution
    environment_distribution = models.JSONField(
        default=dict,
        help_text="Count of active environments across users {development: N, staging: N, production: N}"
    )

    # Integration adoption
    integration_usage = models.JSONField(
        default=dict,
        help_text="Count of users per integration {mcp: N, proxy: N, env: N, sdk: N}"
    )

    computed_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Metrics {self.date}"

    class Meta:
        db_table = 'daily_metrics'
        ordering = ['-date']
        indexes = [
            models.Index(fields=['-date']),
        ]
