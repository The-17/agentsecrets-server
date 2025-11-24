from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
import uuid

from rest_framework_simplejwt.tokens import RefreshToken
from autoslug import AutoSlugField
from .managers import CustomUserManager
from apps.common.models import BaseModel

def slugify_two_fields(self):
    return f"{self.first_name}-{self.last_name}"

AUTH_PROVIDERS = [
        ('google', 'Google'),
        ('email', 'Email')
    ]

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(_('Email Address'), unique=True)
    username = AutoSlugField(
        _("Username"), populate_from=slugify_two_fields, unique=True, always_update=True
    )
    avatar= models.ImageField(upload_to='avatars/', null=True, blank=True)
    auth_provider = models.CharField(max_length=20, choices=AUTH_PROVIDERS, default="email")
    provider_user_id = models.CharField(max_length=255, null=True, blank=True)

    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    terms_agreement = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    encrypted_master_key = models.TextField(null=True, blank=True, help_text="User's master encryption key, encrypted by CLI")
    key_salt = models.TextField(max_length=64, null=True, blank=True, help_text="Salt for deriving password-based key to unwrap master key")

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh':str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")
    
    def __str__(self):
        return self.full_name

class OneTimePassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=100)

    def __str__(self):
        return self.code
    

# class RecoveryCode(models.Model):
#     id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
#     user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recovery_codes')
#     code_hash = models.CharField(max_length=128)
#     encrypted_master_key = models.TextField(null=True, blank=True, help_text="User's master encryption key, encrypted by CLI")
#     is_used = models.BooleanField(default=False)
#     created_at = models.DateTimeField(auto_now_add=True)
#     used_at = models.DateTimeField(null=True, blank=True)

#     class Meta:
#         ordering = ['created_at']
    
#     def __str__(self):
#         return f"{self.user.email} - Recovery Code"