# Django
from django.contrib import admin

# Local
from .models import Project, Secret


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'workspace', 'description', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'workspace__name')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(Secret)
class SecretAdmin(admin.ModelAdmin):
    list_display = ('key', 'project', 'environment', 'created_at', 'updated_at')
    list_filter = ('environment', 'created_at')
    search_fields = ('key', 'project__name')
    readonly_fields = ('id', 'created_at', 'updated_at')
    list_select_related = ('project',)
