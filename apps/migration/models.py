import uuid
from django.db import models
from apps.common.models import BaseModel


class MigrationTokenNonce(BaseModel):
    """Stores used migration token nonces (jti) to prevent replay attacks."""
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    jti = models.CharField(max_length=128, unique=True, db_index=True)
    user_email = models.EmailField()
    used_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = "Migration Token Nonce"
        verbose_name_plural = "Migration Token Nonces"

    def __str__(self):
        return f"{self.user_email} - {self.jti}"
