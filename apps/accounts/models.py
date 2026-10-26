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

import ulid

def generate_billing_id():
    return f"bill_{str(ulid.ULID())}"

def slugify_two_fields(self):
    return f"{self.first_name}-{self.last_name}"

AUTH_PROVIDERS = [
        ('google', 'Google'),
        ('email', 'Email')
    ]

class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    billing_id = models.CharField(
        max_length=64,
        unique=True,
        null=True,
        blank=True,
        default=generate_billing_id,
        help_text="Mandatory AgentSecrets Cloud billing & entitlement identifier"
    )
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
    last_active_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="The last time the user was active on the platform (UTC)"
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

    # Additive v4 vault record. Null for legacy accounts; storing it never
    # removes or rewrites the legacy key blob above.
    vault = models.JSONField(
        null=True,
        blank=True,
        help_text="Opaque client-side vault record: wrapped VK envelopes and proof"
    )
    vault_version = models.PositiveIntegerField(
        default=0,
        help_text="Optimistic concurrency version for the vault record"
    )

    # OPAQUE enrollment. After confirmation, password login is disabled for the account.
    # opaque_record is the SerializedRegistrationRecord sent by the client.
    opaque_record = models.TextField(
        null=True,
        blank=True,
        help_text="Opaque SerializedRegistrationRecord from the client (RFC 9807 client-side)"
    )
    opaque_registered_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when OPAQUE enrollment was confirmed (credentials now unusable via password)"
    )

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @property
    def auth_methods(self) -> set[str]:
        """Enabled auth methods for this account.

        Password and OPAQUE are alternatives: an enrolled account has
        ``opaque`` only, because enrollment clears the password hash. Only the
        new CLI enrolls, so a record means the user upgraded deliberately. Old
        clients keep working on accounts that never enrolled, and need to know
        nothing about OPAQUE. OAuth identities never unlock the vault and stay
        unaffected.
        """
        methods: set[str] = set()
        provider = (self.auth_provider or "email").lower()
        if provider == "google":
            methods.add("oauth_google")
        elif provider == "github":
            methods.add("oauth_github")
        elif self.has_usable_password():
            methods.add("password")
        if self.opaque_record and self.opaque_registered_at:
            methods.add("opaque")
        return methods

    @property
    def password_login_allowed(self) -> bool:
        return "password" in self.auth_methods

    @property
    def opaque_login_allowed(self) -> bool:
        return "opaque" in self.auth_methods

    def save(self, *args, **kwargs):
        if not self.billing_id:
            self.billing_id = generate_billing_id()
        super().save(*args, **kwargs)

    def tokens(self, recovery: bool = False):
        refresh = RefreshToken.for_user(self)
        refresh["email"] = self.email
        refresh["first_name"] = self.first_name
        refresh["last_name"] = self.last_name
        refresh["billing_id"] = self.billing_id
        refresh["is_staff"] = self.is_staff
        refresh["is_superuser"] = self.is_superuser
        if recovery:
            # Marks a session opened by proof of vault-key possession rather
            # than a password. Only such a session may reset the password
            # without knowing the old one.
            refresh["recovery"] = True
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")
        indexes = [
            models.Index(fields=['last_active_at']),
            models.Index(fields=['billing_id']),
        ]
    
    def __str__(self):
        return self.full_name


class OpaqueLoginChallenge(BaseModel):
    """
    Short-lived server state for each OPAQUE login request (TTL 120s).
    Stored to prevent replay: the client consumes the challenge when it returns
    and we safely delete the record after login_finish.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="opaque_login_challenges",
        help_text="User performing OPAQUE login"
    )
    challenge_id = models.CharField(
        max_length=64,
        unique=True,
        help_text="Unique challenge ID"
    )
    expires_at = models.DateTimeField(
        help_text="Challenge expiration (120s from creation)"
    )
    used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the challenge was consumed"
    )
    # oss server_state returned on /v1/login/start, stored for consumption on /v1/login/finish
    server_state = models.BinaryField(
        help_text="Server state blob to prevent replay"
    )

    class Meta:
        verbose_name = _("OPAQUE Login Challenge")
        verbose_name_plural = _("OPAQUE Login Challenges")
        indexes = [
            models.Index(fields=["user", "expires_at"]),
            models.Index(fields=["challenge_id"]),
        ]

    def is_expired(self) -> bool:
        from django.utils import timezone

        return timezone.now() > self.expires_at

    def consume(self) -> None:
        from django.utils import timezone

        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])


class OAuthAuthorizationCode(BaseModel):
    """
    Single-use authorization code for the OAuth 2.1 Authorization Code + PKCE
    flow that powers headless agent login (`auth_login` in the MCP bridge).

    Only the SHA-256 hash of the code is stored — a database read never
    yields a redeemable code. Codes are bound to (client, redirect_uri,
    PKCE challenge) at issuance and claimed atomically at redemption.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="oauth_codes")
    client_id = models.CharField(max_length=128, db_index=True)
    redirect_uri = models.CharField(max_length=2000)
    scope = models.CharField(max_length=512, default="", blank=True)
    code_challenge = models.CharField(max_length=128)
    code_challenge_method = models.CharField(max_length=16, default="S256")
    code_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        # code_hash (unique) and expires_at (db_index) are indexed at the
        # field level; no extra Meta indexes needed.
        ordering = ["-created_at"]

    def __str__(self):
        return f"oauth-code {self.client_id} for {self.user.email}"


class OneTimePassword(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=100)

    def __str__(self):
        return self.code
    

class VaultRecoveryChallenge(models.Model):
    """A single-use nonce a client signs to prove it holds the vault key.

    The challenge text is stored verbatim so the server verifies exactly the
    bytes the client signed. Only the nonce hash is indexed for lookup; the
    nonce itself is returned to the client once and never stored.
    """
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="vault_recovery_challenges"
    )
    nonce_hash = models.CharField(max_length=64, unique=True)
    challenge = models.TextField()
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "created_at"])]

    def __str__(self):
        return f"vault-recovery challenge for {self.user.email}"


class AccountProbe(models.Model):
    """One public account-existence probe, kept only long enough to pace them.

    The auth UI has to ask whether an email is registered before it can show the
    right step, which is enumeration by design. This table is what makes the
    answer rate-limited, and it stores a hashed IP rather than the address so it
    cannot become a record of who checked which account.
    """

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    ip_hash = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["ip_hash", "created_at"])]

    def __str__(self):
        return f"account probe at {self.created_at:%Y-%m-%d %H:%M:%S}"


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