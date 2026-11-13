"""Soft gates that push unverified accounts toward email verification.

Every gate is inert until REQUIRE_EMAIL_VERIFICATION is on. Caps refuse only
the creation that would cross the line. Nothing already stored is hidden,
locked, or removed, so an existing account above a cap keeps working.
"""
from __future__ import annotations

from django.conf import settings

from apps.accounts.models import User
from apps.common.exceptions import ErrorCode, RequestError

FIX = "Verify your email with 'agentsecrets email verify' to continue."


async def is_verified(user: User) -> bool:
    """Read the flag from the database, never from a signed claim.

    A JWT issued before verification stays unverified until a fresh login, so
    a claim-based gate would keep blocking a user who just verified.
    """
    if not settings.REQUIRE_EMAIL_VERIFICATION:
        return True
    return await User.objects.filter(pk=user.pk, is_email_verified=True).aexists()


async def require_verified_email(user: User, *, action: str) -> None:
    if await is_verified(user):
        return
    raise RequestError(
        ErrorCode.UNVERIFIED_USER,
        f"Email verification is required to {action}. {FIX}",
        403,
    )


async def enforce_creation_cap(
    user: User,
    *,
    current: int,
    adding: int,
    limit: int,
    what: str,
) -> None:
    """Refuse a creation that crosses the cap for an unverified account.

    Updating what is already there is always allowed. Adding nothing is always
    allowed, even when the account is already above the cap.
    """
    if adding <= 0 or await is_verified(user):
        return
    if current + adding <= limit:
        return
    raise RequestError(
        ErrorCode.UNVERIFIED_USER,
        f"Unverified accounts can hold up to {limit} {what}. {FIX}",
        403,
    )
