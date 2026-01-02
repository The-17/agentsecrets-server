# Django
from django.contrib import admin

# Local
from .models import Workspace, Membership


@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'type', 'created_at')
    list_filter = ('type', 'created_at')
    search_fields = ('name', 'owner__email')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ('user', 'workspace', 'role', 'status', 'created_at')
    list_filter = ('role', 'status', 'created_at')
    search_fields = ('user__email', 'workspace__name')
    readonly_fields = ('id', 'created_at', 'updated_at')
