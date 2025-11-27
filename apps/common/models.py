from django.db import models
import uuid
from .managers import GetOrNoneManager

class BaseModel(models.Model):
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = GetOrNoneManager()


    class Meta:
        abstract = True