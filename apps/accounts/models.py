# Standard library
import uuid

# Django
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _

# Third-party
from autoslug import AutoSlugField
from rest_framework_simplejwt.tokens import RefreshToken

# Local
from apps.common.models import BaseModel
from .managers import CustomUserManager

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
    last_active_date = models.DateField(
        null=True,
        blank=True,
        help_text="The last date the user was active on the platform (UTC date only)"
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    # Salt for deriving user_key from password (used to decrypt private_key)
    key_salt = models.TextField(max_length=64, null=True, blank=True, help_text="Salt for deriving user_key from password")
    
    # Asymmetric encryption keys for workspace sharing
    public_key = models.TextField(
        null=True, 
        blank=True, 
        help_text="User's public key for encrypting workspace keys (others can encrypt for this user)"
    )
    encrypted_private_key = models.TextField(
        null=True, 
        blank=True, 
        help_text="User's private key encrypted with their derived user_key (only they can decrypt)"
    )

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
        indexes = [
            models.Index(fields=['last_active_date']),
        ]
    
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