# Standard library
import os
import urllib.parse
import ulid
import base62

# Django
from django.db import models

# Local
from apps.accounts.models import User
from apps.common.models import BaseModel


class WorkspaceType(models.TextChoices):
    """Type of workspace"""
    PERSONAL = 'personal', 'Personal'
    SHARED = 'shared', 'Shared'


class MembershipRole(models.TextChoices):
    """Role within a workspace"""
    OWNER = 'owner', 'Owner'
    ADMIN = 'admin', 'Admin'
    MEMBER = 'member', 'Member'
    READ_ONLY = 'read_only', 'Read Only'


class MembershipStatus(models.TextChoices):
    """Status of membership"""
    ACTIVE = 'active', 'Active'
    INVITED = 'invited', 'Invited'


class Workspace(BaseModel):
    """
    Workspace is the security boundary for secrets.
    
    - Personal workspace: auto-created on user registration, contains only that user
    - Shared workspace: created when sharing a project or explicitly by user
    
    Each workspace has its own encryption key (stored encrypted per-user in Membership).
    """
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='owned_workspaces',
        help_text="The user who created/owns this workspace"
    )
    type = models.CharField(
        max_length=20,
        choices=WorkspaceType.choices,
        default=WorkspaceType.SHARED,
        help_text="personal = auto-created on signup, shared = team/project sharing"
    )

    def __str__(self):
        return f"{self.name} ({self.type})"
    
    class Meta:
        db_table = 'workspaces'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', '-created_at']),
            models.Index(fields=['type']),
        ]


class Membership(BaseModel):
    """
    Links users to workspaces with role-based access.
    
    Each membership stores the workspace key encrypted with that user's public key.
    This enables zero-knowledge sharing: the server never sees the plaintext workspace key.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='memberships',
        help_text="The user who is a member of the workspace"
    )
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name='memberships',
        help_text="The workspace this membership belongs to"
    )
    role = models.CharField(
        max_length=20,
        choices=MembershipRole.choices,
        default=MembershipRole.MEMBER,
        help_text="Role determines what actions the user can perform"
    )
    status = models.CharField(
        max_length=20,
        choices=MembershipStatus.choices,
        default=MembershipStatus.ACTIVE,
        help_text="active = full access, invited = pending acceptance"
    )
    encrypted_workspace_key = models.TextField(
        help_text="Workspace key encrypted with this user's public key"
    )

    def __str__(self):
        return f"{self.user.email} - {self.workspace.name} ({self.role})"
    
    class Meta:
        db_table = 'memberships'
        ordering = ['-created_at']
        unique_together = ('user', 'workspace')
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['workspace', 'role']),
        ]


class WorkspaceAllowlist(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name='allowlist'
    )
    domain = models.CharField(max_length=253)  # max domain length per RFC
    added_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('workspace', 'domain')
        ordering = ['added_at']

    def __str__(self):
        return f"{self.domain} in {self.workspace.name}"


class WorkspaceAllowlistLog(models.Model):
    ACTION_CHOICES = [
        ('added', 'Added'),
        ('removed', 'Removed'),
    ]

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name='allowlist_logs'
    )
    domain = models.CharField(max_length=253)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True
    )
    performed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-performed_at']
        indexes = [
            models.Index(fields=['workspace', '-performed_at']),
        ]

    def __str__(self):
        return f"{self.action} {self.domain} in {self.workspace.name}"


def generate_areg_id():
    return f"areg_{str(ulid.ULID())}"


def generate_log_id():
    return f"log_{str(ulid.ULID())}"


class AgentRegistration(models.Model):
    id = models.CharField(primary_key=True, max_length=31, default=generate_areg_id, editable=False)
    workspace = models.ForeignKey(
        Workspace, on_delete=models.CASCADE, related_name='agents',
        help_text="Workspace this agent is registered to"
    )
    project = models.ForeignKey(
        'secrets_app.Project', on_delete=models.CASCADE, related_name='agents',
        null=True, blank=True,
        help_text="Project this agent is registered to (if project-scoped)"
    )
    name = models.CharField(max_length=64, help_text="Human-readable agent name")
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='created_agents'
    )

    class Meta:
        db_table = 'agent_registrations'
        constraints = [
            models.UniqueConstraint(
                fields=['workspace', 'name'],
                condition=models.Q(project__isnull=True),
                name='unique_workspace_agent_name'
            ),
            models.UniqueConstraint(
                fields=['project', 'name'],
                condition=models.Q(project__isnull=False),
                name='unique_project_agent_name'
            )
        ]

    def __str__(self):
        return self.name


class AgentToken(models.Model):
    id = models.CharField(primary_key=True, max_length=100, editable=False)
    registration = models.ForeignKey(
        AgentRegistration, on_delete=models.CASCADE, related_name='tokens'
    )
    workspace = models.ForeignKey(
        Workspace, on_delete=models.CASCADE, related_name='agent_tokens'
    )
    environment = models.CharField(max_length=20, default='development')
    token_hash = models.CharField(max_length=64, help_text="HMAC-SHA256 of the raw token value")
    label = models.CharField(max_length=255, null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='created_agent_tokens'
    )

    class Meta:
        db_table = 'agent_tokens'

    def save(self, *args, **kwargs):
        if not self.id:
            ws_short = str(self.workspace_id)[:8].lower().replace('-', '')
            random_bytes = os.urandom(32)
            b62_str = base62.encodebytes(random_bytes)
            self.id = f"agt_{ws_short}_{b62_str}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.registration.name} - {self.label or 'token'}"


class IdentityLevel(models.TextChoices):
    ANONYMOUS = 'anonymous', 'Anonymous'
    DECLARED = 'declared', 'Declared'
    ISSUED = 'issued', 'Issued'


class AuditLogEntry(models.Model):
    id = models.CharField(primary_key=True, max_length=64, default=generate_log_id, editable=False)
    schema_version = models.IntegerField(default=1)
    
    timestamp = models.DateTimeField()
    recorded_at = models.DateTimeField(auto_now_add=True)
    
    environment = models.CharField(max_length=20, default='development', null=True, blank=True)
    workspace = models.ForeignKey(
        Workspace, on_delete=models.CASCADE, related_name='audit_logs'
    )
    project = models.ForeignKey(
        'secrets_app.Project', on_delete=models.CASCADE, related_name='audit_logs',
        null=True, blank=True
    )
    
    agent_id = models.CharField(max_length=64, null=True, blank=True)
    agent_token = models.ForeignKey(
        AgentToken, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='audit_logs'
    )
    identity_level = models.CharField(
        max_length=20, choices=IdentityLevel.choices, default=IdentityLevel.ANONYMOUS
    )
    
    credential_ref = models.CharField(max_length=255)
    injection_style = models.CharField(max_length=50)
    
    target_domain = models.CharField(max_length=253)
    target_url = models.TextField()
    target_path = models.TextField()
    method = models.CharField(max_length=10)
    
    status_code = models.IntegerField(null=True, blank=True)
    duration_ms = models.IntegerField()
    proxy_duration_ms = models.IntegerField(default=0)
    
    redacted = models.BooleanField(default=False)
    redaction_reason = models.CharField(max_length=255, null=True, blank=True)
    
    resolution_path = models.CharField(max_length=50)
    
    allowlist_snapshot = models.JSONField(default=dict)
    caller_role = models.CharField(max_length=50)
    
    session_id = models.CharField(max_length=255, null=True, blank=True)
    policy_snapshot_id = models.CharField(max_length=255, null=True, blank=True)
    error = models.JSONField(null=True, blank=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['workspace', '-timestamp']),
            models.Index(fields=['agent_token', '-timestamp']),
            models.Index(fields=['target_domain', '-timestamp']),
        ]

    def __str__(self):
        s = f"{self.identity_level} -> {self.target_domain}"
        if self.agent_id:
            s = f"{self.agent_id} ({self.identity_level}) -> {self.target_domain}"
        return s

