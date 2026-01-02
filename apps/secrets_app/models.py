# Django
from django.db import models

# Local
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
    key = models.CharField(max_length=255)
    value = models.TextField()
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='secrets')

    def __str__(self):
        return f"{self.key} - {self.project.name}"

    class Meta:
        db_table = 'secrets'
        ordering = ['key']
        unique_together = [['project', 'key']]
        indexes = [
            models.Index(fields=['project', 'key']),
            models.Index(fields=['project', '-updated_at']),
        ]
