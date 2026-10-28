"""Batched in-place re-encryption during platform key rotation.

The production write key is trapped in the deployment provider's environment
store and cannot be exported, so rotation happens by re-encryption: each row
holding ciphertext from the original key is read with it and written back in
the current write format (under ENCRYPTION_KEY_NEXT, versioned "v2:"). The
dataset is drained in bounded batches, cursor by primary key.

Two properties matter here:

- **Idempotent.** A row already on the current write key is left untouched, and
  the endpoint refuses to run at all when rotation is inactive, so a batch
  rerun after a crash makes no second pass over the same tokens.
- **Fail closed.** A row that cannot be decrypted is reported by primary key
  and left exactly as it stands — never overwritten, never dropped.

Secret values never appear in any return value; only primary keys and counts.
"""

# Standard library
import secrets as pysecrets

# Django
from django.conf import settings

# Local
from apps.accounts.models import User
from apps.common.services.encryption import EncryptionService
from apps.secrets_app.models import Secret


def check_rotation_token(presented: str) -> bool:
    """Constant-time check of the operator token against settings.

    Fails closed: without ROTATION_TOKEN configured the sweep endpoint rejects
    every call, with or without a presented token.
    """
    expected = getattr(settings, "ROTATION_TOKEN", "")
    if not expected:
        return False
    return bool(presented) and pysecrets.compare_digest(presented, expected)


def _remaining_secrets() -> int:
    """Rows still on the original key (any non-v2 value)."""
    return Secret.objects.exclude(value__startswith="v2:").count()


def _remaining_key_salts() -> int:
    """Users still holding a key_salt from the original key (nulls excluded)."""
    return (
        User.objects.exclude(key_salt__isnull=True)
        .exclude(key_salt__startswith="v2:")
        .count()
    )


def _rewrap_rows(rows, column: str) -> tuple[int, list, int]:
    """Rewrap one bounded pk-ordered slice; return (rewrapped, skipped pks, last pk)."""
    rewrapped = 0
    skipped: list[int] = []
    last_pk = 0
    for row in rows:
        last_pk = row.pk
        current = getattr(row, column)
        if not EncryptionService.needs_rewrap(current):
            continue
        plain = EncryptionService.try_decrypt(current)
        if plain is None:
            # Report, do not destroy. The operator decides what to do with a
            # row the old key cannot read; deleting it would be the one
            # irreversible act in this module.
            skipped.append(row.pk)
            continue
        setattr(row, column, EncryptionService.encrypt(plain))
        row.save(update_fields=[column])
        rewrapped += 1
    return rewrapped, skipped, last_pk


def rewrap_batch(secret_cursor: int = 0, salt_cursor: int = 0, limit: int = 200) -> dict:
    """Re-encrypt up to ``limit`` rows per table past the given cursors.

    Only runs while rotation is active, because otherwise it would rewrite
    ciphertext back under the same key — churn with no effect that would also
    keep the "remaining on the original key" counts permanently nonzero.
    """
    if not getattr(settings, "ENCRYPTION_KEY_NEXT", ""):
        raise RuntimeError(
            "rotation inactive: ENCRYPTION_KEY_NEXT is not set, "
            "so a sweep would rewrite rows under the same key they already use"
        )
    limit = max(1, min(limit, 1000))

    # Peek one row past the batch: with len <= limit the table is exhausted,
    # so a full-limit batch does not look identical to "nothing more".
    secret_rows = list(
        Secret.objects.filter(pk__gt=secret_cursor).order_by("pk")[: limit + 1]
    )
    s_done = len(secret_rows) <= limit
    secret_rows = secret_rows[:limit]

    salt_rows = list(
        User.objects.filter(key_salt__isnull=False, pk__gt=salt_cursor)
        .order_by("pk")[: limit + 1]
    )
    u_done = len(salt_rows) <= limit
    salt_rows = salt_rows[:limit]

    s_rewrapped, s_skipped, s_last = _rewrap_rows(secret_rows, "value")
    u_rewrapped, u_skipped, u_last = _rewrap_rows(salt_rows, "key_salt")

    return {
        "secrets": {
            "scanned": len(secret_rows),
            "rewrapped": s_rewrapped,
            "skipped": s_skipped,
            "cursor": s_last,
            "done": s_done,
            "remaining": _remaining_secrets(),
        },
        "key_salts": {
            "scanned": len(salt_rows),
            "rewrapped": u_rewrapped,
            "skipped": u_skipped,
            "cursor": u_last,
            "done": u_done,
            "remaining": _remaining_key_salts(),
        },
        "finished": s_done and u_done,
    }
