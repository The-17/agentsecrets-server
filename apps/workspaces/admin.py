# Django
from django.contrib import admin

# Third-party
from unfold.admin import ModelAdmin, TabularInline

# Local
from .models import (
    Workspace, Membership,
    WorkspaceAllowlist, WorkspaceAllowlistLog,
    AgentRegistration, AgentToken, AuditLogEntry
)
from apps.secrets_app.models import Project


class ProjectInline(TabularInline):
    model = Project
    extra = 0
    readonly_fields = ('id', 'name', 'created_at', 'updated_at')
    tab = True

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class WorkspaceAllowlistInline(TabularInline):
    model = WorkspaceAllowlist
    extra = 0
    readonly_fields = ('domain', 'added_by', 'added_at')
    tab = True

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Workspace)
class WorkspaceAdmin(ModelAdmin):
    list_display = ('name', 'owner', 'type', 'project_count', 'created_at')
    list_filter = ('type', 'created_at')
    search_fields = ('name', 'owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')
    inlines = [ProjectInline, WorkspaceAllowlistInline]

    def project_count(self, obj):
        return obj.projects.count()
    project_count.short_description = "Projects"


@admin.register(Membership)
class MembershipAdmin(ModelAdmin):
    list_display = ('user', 'workspace', 'role', 'status', 'created_at')
    list_filter = ('role', 'status', 'created_at')
    search_fields = ('user__email', 'workspace__name')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(WorkspaceAllowlist)
class WorkspaceAllowlistAdmin(ModelAdmin):
    list_display = ('domain', 'workspace', 'added_by', 'added_at')
    list_filter = ('added_at',)
    search_fields = ('domain', 'workspace__name')


@admin.register(WorkspaceAllowlistLog)
class WorkspaceAllowlistLogAdmin(ModelAdmin):
    list_display = ('domain', 'action', 'workspace', 'performed_by', 'performed_at')
    list_filter = ('action', 'performed_at')
    search_fields = ('domain', 'workspace__name')
    date_hierarchy = 'performed_at'


@admin.register(AgentRegistration)
class AgentRegistrationAdmin(ModelAdmin):
    list_display = ('name', 'workspace', 'project', 'created_by', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'workspace__name', 'created_by__email')


@admin.register(AgentToken)
class AgentTokenAdmin(ModelAdmin):
    list_display = ('registration', 'workspace', 'environment', 'label', 'expires_at', 'revoked_at', 'created_at')
    list_filter = ('environment', 'created_at')
    search_fields = ('registration__name', 'label')
    readonly_fields = ('id', 'token_hash', 'created_at')


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(ModelAdmin):
    list_display = ('timestamp', 'workspace', 'project', 'identity_level', 'agent_id', 'credential_ref', 'target_domain', 'method', 'status_code', 'duration_ms')
    list_filter = ('workspace', 'project', 'identity_level', 'method', 'environment', 'redacted', 'timestamp')
    search_fields = ('agent_id', 'credential_ref', 'target_domain', 'workspace__name', 'project__name')
    readonly_fields = ('id', 'recorded_at')
    date_hierarchy = 'timestamp'
