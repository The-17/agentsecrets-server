"""The break-glass gate for password login on OPAQUE-enrolled accounts.

Enrollment clears the password hash, so a normal enrolled account cannot
authenticate by password no matter what this gate says: there is nothing to
check. The gate exists for the recovery window, when an operator has restored a
hash with ``set_password`` and needs the account working before the sidecar is
back, without a deploy.
"""

import logging
import os

logger = logging.getLogger("apps.accounts")


def opaque_sidecar_password_gate() -> bool:
    """Whether the loud, temporary password break-glass is open.

    Read at call time, never cached, so setting the env var takes effect on the
    next request and removing it closes the path just as fast.
    """
    enabled = os.environ.get("OPAQUE_ALLOW_PASSWORD", "").strip().lower() == "true"
    if enabled:
        logger.warning(
            "OPAQUE_ALLOW_PASSWORD is set: password login is temporarily "
            "re-enabled for enrolled accounts. Remove it once the sidecar or "
            "the account is repaired."
        )
    return enabled
