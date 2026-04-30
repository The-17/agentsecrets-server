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


class PublicMetricsSerializer(serializers.Serializer):
    """
    Serializer for the public-facing metrics endpoint.
    
    Powers the website stats display (secrets stored, active projects, etc.).
    No sensitive data — only aggregate counts.
    """
    total_secrets_stored = serializers.IntegerField(read_only=True)
    active_projects = serializers.IntegerField(read_only=True)
    total_users = serializers.IntegerField(read_only=True)
    total_proxy_calls = serializers.IntegerField(read_only=True)
    shared_workspaces = serializers.IntegerField(read_only=True)
    total_environments_configured = serializers.IntegerField(read_only=True)
