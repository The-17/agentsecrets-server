# Django
from django.contrib import admin

# Third-party
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from unfold.admin import ModelAdmin

# Local
from .models import User, OneTimePassword


@admin.register(User)
class UserAdmin(BaseUserAdmin, ModelAdmin):
    list_display = ('email', 'first_name', 'last_name', 'auth_provider', 'is_active', 'is_email_verified', 'created_at')
    list_filter = ('auth_provider', 'is_active', 'is_email_verified', 'is_staff', 'created_at')
    search_fields = ('email', 'first_name', 'last_name')
    readonly_fields = ('id', 'created_at', 'updated_at')
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'avatar')}),
        ('Auth', {'fields': ('auth_provider', 'provider_user_id')}),
        ('Encryption Keys', {'fields': ('key_salt', 'public_key', 'encrypted_private_key')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_email_verified', 'terms_agreement')}),
        ('Timestamps', {'fields': ('created_at', 'updated_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2'),
        }),
    )


@admin.register(OneTimePassword)
class OneTimePasswordAdmin(ModelAdmin):
    list_display = ('user', 'code')
    search_fields = ('user__email',)
