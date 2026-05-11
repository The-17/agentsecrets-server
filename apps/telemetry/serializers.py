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
