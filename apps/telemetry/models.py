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

    # v3.0.0 Core
    secrets_resolved = models.IntegerField(default=0)
    total_proxy_duration_ms = models.BigIntegerField(default=0)

    # Execution Path Breakdown
    proxy_calls_daemon = models.IntegerField(default=0)
    proxy_calls_transient = models.IntegerField(default=0)
    proxy_calls_mcp = models.IntegerField(default=0)
    proxy_calls_direct = models.IntegerField(default=0)
    developer_commands = models.IntegerField(default=0)

    # Agentic Shielding
    ssrf_attempts_blocked = models.IntegerField(default=0)
    allowlist_violations = models.IntegerField(default=0)
    response_redactions = models.IntegerField(default=0)
    process_verifications_failed = models.IntegerField(default=0)
    production_write_challenges = models.IntegerField(default=0)

    # Latency & Performance
    keychain_resolution_ms = models.BigIntegerField(default=0)
    session_refresh_ms = models.BigIntegerField(default=0)

    # Onboarding & Friction
    interactive_prompts_shown = models.IntegerField(default=0)
    interactive_prompts_skipped = models.IntegerField(default=0)
    drift_diffs_detected = models.IntegerField(default=0)

    # Cryptographic Integrity
    log_chain_verifications = models.IntegerField(default=0)
    tampering_detected = models.IntegerField(default=0)

    # Node Metadata
    is_headless_node = models.BooleanField(default=False)
    keychain_initialized = models.BooleanField(default=False)

    # Typos
    typos = models.JSONField(default=dict)

    # Agent Identity & Capabilities
    identity_anonymous_calls = models.IntegerField(default=0)
    identity_declared_calls = models.IntegerField(default=0)
    identity_issued_calls = models.IntegerField(default=0)
    capability_violations_blocked = models.IntegerField(default=0)
    process_verifications_passed = models.IntegerField(default=0)

    # Granular Error Categories
    errors_auth_count = models.IntegerField(default=0)
    errors_keychain_count = models.IntegerField(default=0)
    errors_secrets_count = models.IntegerField(default=0)
    errors_network_count = models.IntegerField(default=0)
    errors_system_count = models.IntegerField(default=0)
    errors_unknown_count = models.IntegerField(default=0)

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

    # v3 Core
    total_secrets_resolved = models.IntegerField(default=0)
    total_proxy_duration_ms = models.BigIntegerField(default=0)

    # Execution Paths
    total_proxy_calls_daemon = models.IntegerField(default=0)
    total_proxy_calls_transient = models.IntegerField(default=0)
    total_proxy_calls_mcp = models.IntegerField(default=0)
    total_proxy_calls_direct = models.IntegerField(default=0)
    total_developer_commands = models.IntegerField(default=0)

    # Shielding
    total_ssrf_blocked = models.IntegerField(default=0)
    total_allowlist_violations = models.IntegerField(default=0)
    total_redactions_performed = models.IntegerField(default=0)
    total_process_verifications_failed = models.IntegerField(default=0)
    total_production_write_challenges = models.IntegerField(default=0)

    # Latency (Averages will be calculated from ms / total)
    avg_keychain_resolution_ms = models.FloatField(default=0.0)
    avg_session_refresh_ms = models.FloatField(default=0.0)

    # Onboarding
    total_interactive_prompts_shown = models.IntegerField(default=0)
    total_interactive_prompts_skipped = models.IntegerField(default=0)
    total_drift_diffs_detected = models.IntegerField(default=0)

    # Integrity
    total_log_verifications = models.IntegerField(default=0)
    total_tampering_alerts = models.IntegerField(default=0)

    # Node Metadata
    total_headless_nodes = models.IntegerField(default=0)
    total_active_keychains = models.IntegerField(default=0)

    # Identity & Capabilities
    total_identity_anonymous_calls = models.IntegerField(default=0)
    total_identity_declared_calls = models.IntegerField(default=0)
    total_identity_issued_calls = models.IntegerField(default=0)
    total_capability_violations_blocked = models.IntegerField(default=0)
    total_process_verifications_passed = models.IntegerField(default=0)

    # Errors
    total_errors_auth = models.IntegerField(default=0)
    total_errors_keychain = models.IntegerField(default=0)
    total_errors_secrets = models.IntegerField(default=0)
    total_errors_network = models.IntegerField(default=0)
    total_errors_system = models.IntegerField(default=0)
    total_errors_unknown = models.IntegerField(default=0)

    # Typos distribution
    typos_usage = models.JSONField(
        default=dict,
        help_text="Aggregated typos usage across all users for this day"
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
