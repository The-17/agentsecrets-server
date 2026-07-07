# Third-party
from rest_framework import serializers


class TelemetrySyncSerializer(serializers.Serializer):
    """
    Validates the CLI telemetry sync payload.
    
    The CLI batches telemetry locally and sends it every 24 hours.
    All fields except command_executions are optional to support
    older CLI versions that don't send the full payload.
    """
    timestamp = serializers.DateTimeField(
        required=False,
        help_text="Client-side timestamp when telemetry was generated"
    )
    date = serializers.DateField(
        required=False,
        help_text="The date this telemetry bucket represents (YYYY-MM-DD)"
    )
    command_executions = serializers.DictField(
        child=serializers.IntegerField(min_value=0),
        help_text="Map of command name to execution count"
    )

    # CLI environment (optional — older CLIs won't send these)
    cli_version = serializers.CharField(max_length=20, required=False, allow_blank=True, allow_null=True)
    os = serializers.CharField(max_length=50, required=False, allow_blank=True, allow_null=True)
    arch = serializers.CharField(max_length=20, required=False, allow_blank=True, allow_null=True)

    # Workspace context
    active_environment = serializers.ChoiceField(
        choices=['development', 'staging', 'production'],
        required=False,
        allow_blank=True,
        allow_null=True
    )
    workspace_type = serializers.ChoiceField(
        choices=['personal', 'shared'],
        required=False,
        allow_blank=True,
        allow_null=True
    )
    workspace_member_count = serializers.IntegerField(min_value=0, required=False, allow_null=True)
    project_secret_count = serializers.IntegerField(min_value=0, required=False, allow_null=True)

    # Context IDs for server-side enrichment
    workspace_id = serializers.UUIDField(required=False, allow_null=True)
    project_id = serializers.UUIDField(required=False, allow_null=True)

    # User attribution (fallback when JWT is expired/anonymous)
    user_email = serializers.EmailField(required=False, allow_null=True, allow_blank=True)

    # Proxy metrics
    proxy_calls = serializers.IntegerField(min_value=0, required=False, default=0)
    proxy_blocked = serializers.IntegerField(min_value=0, required=False, default=0)
    proxy_redacted = serializers.IntegerField(min_value=0, required=False, default=0)

    # Injection styles and integrations
    injection_styles_used = serializers.ListField(
        child=serializers.CharField(max_length=20),
        required=False,
        default=[]
    )
    integrations_active = serializers.ListField(
        child=serializers.CharField(max_length=20),
        required=False,
        default=[]
    )

    # v3.0.0 Core
    secrets_resolved = serializers.IntegerField(min_value=0, required=False, default=0)
    total_proxy_duration_ms = serializers.IntegerField(min_value=0, required=False, default=0)

    # Execution Path Breakdown
    proxy_calls_daemon = serializers.IntegerField(min_value=0, required=False, default=0)
    proxy_calls_transient = serializers.IntegerField(min_value=0, required=False, default=0)
    proxy_calls_mcp = serializers.IntegerField(min_value=0, required=False, default=0)
    proxy_calls_direct = serializers.IntegerField(min_value=0, required=False, default=0)
    developer_commands = serializers.IntegerField(min_value=0, required=False, default=0)

    # Agentic Shielding
    ssrf_attempts_blocked = serializers.IntegerField(min_value=0, required=False, default=0)
    allowlist_violations = serializers.IntegerField(min_value=0, required=False, default=0)
    response_redactions = serializers.IntegerField(min_value=0, required=False, default=0)
    process_verifications_failed = serializers.IntegerField(min_value=0, required=False, default=0)
    production_write_challenges = serializers.IntegerField(min_value=0, required=False, default=0)

    # Latency & Performance
    keychain_resolution_ms = serializers.IntegerField(min_value=0, required=False, default=0)
    session_refresh_ms = serializers.IntegerField(min_value=0, required=False, default=0)

    # Onboarding & Friction
    interactive_prompts_shown = serializers.IntegerField(min_value=0, required=False, default=0)
    interactive_prompts_skipped = serializers.IntegerField(min_value=0, required=False, default=0)
    drift_diffs_detected = serializers.IntegerField(min_value=0, required=False, default=0)

    # Cryptographic Integrity
    log_chain_verifications = serializers.IntegerField(min_value=0, required=False, default=0)
    tampering_detected = serializers.IntegerField(min_value=0, required=False, default=0)

    # Node Metadata
    is_headless_node = serializers.BooleanField(required=False, default=False)
    keychain_initialized = serializers.BooleanField(required=False, default=False)

    # Typos
    typos = serializers.DictField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        allow_null=True,
        default=dict
    )

    # Agent Identity & Capabilities
    identity_anonymous_calls = serializers.IntegerField(min_value=0, required=False, default=0)
    identity_declared_calls = serializers.IntegerField(min_value=0, required=False, default=0)
    identity_issued_calls = serializers.IntegerField(min_value=0, required=False, default=0)
    capability_violations_blocked = serializers.IntegerField(min_value=0, required=False, default=0)
    process_verifications_passed = serializers.IntegerField(min_value=0, required=False, default=0)

    # Granular Error Categories
    errors_auth_count = serializers.IntegerField(min_value=0, required=False, default=0)
    errors_keychain_count = serializers.IntegerField(min_value=0, required=False, default=0)
    errors_secrets_count = serializers.IntegerField(min_value=0, required=False, default=0)
    errors_network_count = serializers.IntegerField(min_value=0, required=False, default=0)
    errors_system_count = serializers.IntegerField(min_value=0, required=False, default=0)
    errors_unknown_count = serializers.IntegerField(min_value=0, required=False, default=0)


from .models import DailyMetricsAggregate


class PublicMetricsSerializer(serializers.ModelSerializer):
    """
    Serializer for the platform metrics.
    
    Provides both public vanity stats for the landing page and detailed
    aggregates for internal monitoring (averages, usage trends, etc.).
    """
    class Meta:
        model = DailyMetricsAggregate
        fields = '__all__'
