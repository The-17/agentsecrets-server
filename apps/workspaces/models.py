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
