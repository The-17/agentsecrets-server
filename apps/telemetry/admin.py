# Django
from django.contrib import admin

# Local
from .models import TelemetrySnapshot, DailyMetricsAggregate


@admin.register(TelemetrySnapshot)
class TelemetrySnapshotAdmin(admin.ModelAdmin):
    list_display = ('user', 'cli_version', 'os', 'proxy_calls', 'created_at')
    list_filter = ('os', 'cli_version', 'active_environment', 'workspace_type', 'created_at')
    search_fields = ('user__email',)
    readonly_fields = ('id', 'created_at', 'updated_at')
    date_hierarchy = 'created_at'


@admin.register(DailyMetricsAggregate)
class DailyMetricsAggregateAdmin(admin.ModelAdmin):
    list_display = (
        'date', 'total_users', 'active_users_daily', 'total_projects',
        'total_secrets', 'total_proxy_calls', 'shared_workspaces'
    )
    list_filter = ('date',)
    readonly_fields = ('computed_at',)
    date_hierarchy = 'date'
