# Django
from django.conf import settings

# Third-party
from cryptography.fernet import Fernet, InvalidToken


# Versioned ciphertext.
#
# The current production key is trapped in Vercel's environment store: it can
# be read by the running deployment but never exported. Rotation therefore
# happens in place — a new key arrives as ENCRYPTION_KEY_NEXT, every write uses
# it, and a batched sweep re-encrypts the old rows until none are left on the
# original key. After the sweep the new host carries only the new value.
#
# Wire format: unprefixed means the original key; "v2:" means
# ENCRYPTION_KEY_NEXT. The prefix is unambiguous because Fernet tokens are
# url-safe base64, which has no colon, so an unprefixed token can never start
# with "v2:".
V2_PREFIX = "v2:"


def _current_cipher() -> Fernet:
    return Fernet(settings.ENCRYPTION_KEY)


def _next_cipher() -> Fernet | None:
    next_key = getattr(settings, "ENCRYPTION_KEY_NEXT", "")
    return Fernet(next_key) if next_key else None


class EncryptionService:
    @staticmethod
    def encrypt(data: str) -> str:
        """Encrypt with the current write key.

        When ENCRYPTION_KEY_NEXT is set it becomes the write key and the
        ciphertext is versioned; otherwise the original key keeps writing its
        original unversioned format, so behaviour is unchanged until an operator
        opts into rotation.
        """
        next_cipher = _next_cipher()
        if next_cipher is not None:
            return V2_PREFIX + next_cipher.encrypt(data.encode()).decode()
        return _current_cipher().encrypt(data.encode()).decode()

    @staticmethod
    def decrypt(encrypted_data: str) -> str:
        token = encrypted_data
        if token.startswith(V2_PREFIX):
            next_cipher = _next_cipher()
            if next_cipher is None:
                # Fail closed rather than decrypting with the wrong key: a v2
                # row cannot be read without the key that wrote it.
                raise RuntimeError(
                    "ciphertext is v2 but ENCRYPTION_KEY_NEXT is not set; "
                    "set it to decrypt rows written during key rotation"
                )
            return next_cipher.decrypt(token[len(V2_PREFIX):].encode()).decode()
        return _current_cipher().decrypt(token.encode()).decode()

    @staticmethod
    def needs_rewrap(encrypted_data: str) -> bool:
        """Whether this ciphertext is still on the original key."""
        return not encrypted_data.startswith(V2_PREFIX)

    @staticmethod
    def try_decrypt(encrypted_data: str) -> str | None:
        """Decrypt, returning None on failure instead of raising.

        The sweep uses this to re-encrypt with the current key only when the
        old key can actually read the row; a row that cannot be decrypted is
        left alone and reported rather than destroyed.
        """
        try:
            return EncryptionService.decrypt(encrypted_data)
        except (InvalidToken, RuntimeError):
            return None
