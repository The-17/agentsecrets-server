# Django
from django.contrib import admin

# Third-party
from unfold.admin import ModelAdmin, TabularInline

# Local
from .models import Project, Secret


class SecretInline(TabularInline):
    model = Secret
    extra = 0
    readonly_fields = ('id', 'key', 'environment', 'created_at', 'updated_at')
    tab = True

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Project)
class ProjectAdmin(ModelAdmin):
    list_display = ('name', 'workspace', 'secret_count', 'description', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'workspace__name')
    readonly_fields = ('id', 'created_at', 'updated_at')
    inlines = [SecretInline]

    def secret_count(self, obj):
        return obj.secrets.count()
    secret_count.short_description = "Secrets"


@admin.register(Secret)
class SecretAdmin(ModelAdmin):
    list_display = ('key', 'project', 'environment', 'created_at', 'updated_at')
    list_filter = ('environment', 'created_at')
    search_fields = ('key', 'project__name')
    readonly_fields = ('id', 'created_at', 'updated_at')
    list_select_related = ('project',)
