from apps.common.models import BaseModel
from apps.accounts.models import User
from django.db import models



class Project(BaseModel):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='projects')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    

    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'projects'
        ordering = ['-created_at']
        unique_together = ('owner', 'name')
        indexes = [
            models.Index(fields=['owner', 'name']),
            models.Index(fields=['owner', '-created_at']),
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
