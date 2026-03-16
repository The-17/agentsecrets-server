# Django
from django.conf import settings

# Third-party
from cryptography.fernet import Fernet


# Cached at import time — avoid re-creating the cipher on every call
_fernet = Fernet(settings.ENCRYPTION_KEY)


class EncryptionService:
    @staticmethod
    def encrypt(data: str) -> str:
        return _fernet.encrypt(data.encode()).decode()

    @staticmethod
    def decrypt(encrypted_data: str) -> str:
        return _fernet.decrypt(encrypted_data.encode()).decode()

