# Django
from django.conf import settings

# Third-party
from cryptography.fernet import Fernet


ENCRYPTION_KEY = settings.ENCRYPTION_KEY


class EncryptionService:
    @staticmethod
    def encrypt(data: str) -> str:
        fernet = Fernet(ENCRYPTION_KEY)
        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data.decode()

    @staticmethod
    def decrypt(encrypted_data: str) -> str:
        fernet = Fernet(ENCRYPTION_KEY)
        decrypted_data = fernet.decrypt(encrypted_data.encode())
        return decrypted_data.decode()

