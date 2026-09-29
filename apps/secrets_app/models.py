# Django
from django.db import models
from django.db.models import Q

# Local
from apps.accounts.models import User
from apps.common.models import BaseModel
from apps.workspaces.models import Workspace


class Project(BaseModel):
    """
    Project contains secrets and belongs to a workspace.
    
    - Personal projects: belong to user's personal workspace
    - Shared projects: belong to a shared workspace with multiple members
    """
    workspace = models.ForeignKey(
        Workspace, 
        on_delete=models.CASCADE, 
        related_name='projects',
        help_text="Workspace this project belongs to",
        blank=True,
        null=True
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'projects'
        ordering = ['-created_at']
        unique_together = ('workspace', 'name')
        indexes = [
            models.Index(fields=['workspace', 'name']),
            models.Index(fields=['workspace', '-created_at']),
        ]
    

class Secret(BaseModel):
    environment = models.CharField(max_length=20, default='development')
    key = models.CharField(max_length=255)
    value = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='secrets')
    policy = models.JSONField(
        default=dict, blank=True,
        help_text="Usage policy: allowed domains and HTTP methods"
    )
    rotation_type = models.CharField(
        max_length=20, default='none', db_index=True,
        choices=[
            ('none', 'None'),
            ('value_client', 'Client/CI push (B1)'),
            ('value_auto', 'Resolver-autonomous (B2)'),
            ('value_provider', 'Provider-minted (B3)'),
        ],
        help_text="Rotation class; arming is desired-state only, execution is Pro-gated in the resolver (HR-M3)"
    )
    rotation_binding = models.JSONField(
        default=dict, blank=True,
        help_text="B2 mint params (mode/length_bytes/encoding); B3 adapter id + admin credential ref"
    )
    rotation_period = models.DurationField(null=True, blank=True)
    rotation_overlap = models.DurationField(
        null=True, blank=True,
        help_text="Routine-rotation grace window; null means the 24h default"
    )
    next_rotation_at = models.DateTimeField(null=True, blank=True, db_index=True)

    def __str__(self):
        return f"{self.key} - {self.project.name} ({self.environment})"

    class Meta:
        db_table = 'secrets'
        ordering = ['key']
        unique_together = [['project', 'environment', 'key']]
        indexes = [
            models.Index(fields=['project', 'environment']),
            models.Index(fields=['project', 'key']),
            models.Index(fields=['project', '-updated_at']),
        ]


class SecretVersion(BaseModel):
    """Archive table for value rotation (ROTATION_PLAN §3).

    The hot `secrets` row stays single-valued (B-2); pending/current/previous
    ciphertexts live here. Ciphertext is stored in the same double-wrapped
    form as the hot row (server Fernet envelope over the client's DEK
    ciphertext) so promote is a pointer flip — the server never handles
    plaintext. Exactly one `pending` and one `current` row may exist per
    secret (partial unique indexes, HR-H2).
    """
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE, related_name='versions')
    ciphertext = models.TextField()
    staging_label = models.CharField(
        max_length=20, db_index=True,
        choices=[('pending', 'Pending'), ('current', 'Current'), ('previous', 'Previous')],
    )
    rotation_reason = models.CharField(
        max_length=20, default='routine',
        choices=[('routine', 'Routine'), ('compromise', 'Compromise')],
    )
    rotation_id = models.CharField(
        max_length=100, null=True, blank=True, db_index=True,
        help_text="Idempotency key of the rotation cycle that created this version (HR-H4)"
    )
    provider_binding = models.JSONField(
        default=dict, blank=True,
        help_text="B1: {'mode': 'out-of-band'}; B2/B3: adapter id + admin credential ref"
    )
    overlap_until = models.DateTimeField(
        null=True, blank=True,
        help_text="Previous row becomes reapable after this time (routine only)"
    )
    revoked_at = models.DateTimeField(
        null=True, blank=True,
        help_text="Poisoned (compromise): never a rollback target, never promotable (HR-H3)"
    )
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_secret_versions')

    def __str__(self):
        return f"{self.secret.key} [{self.staging_label}]"

    class Meta:
        db_table = 'secret_versions'
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(
                fields=['secret'], condition=Q(staging_label='pending'),
                name='uniq_pending_version_per_secret',
            ),
            models.UniqueConstraint(
                fields=['secret'], condition=Q(staging_label='current'),
                name='uniq_current_version_per_secret',
            ),
        ]
        indexes = [
            models.Index(fields=['secret', 'staging_label']),
            models.Index(fields=['secret', '-created_at']),
        ]
