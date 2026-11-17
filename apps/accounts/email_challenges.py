"""Email challenge lifecycle: issue, deliver, consume.

One challenge per user, bound to a purpose and the address it was sent to. Codes
expire, are single-use, and tolerate only a handful of guesses. Delivery is
fail-closed. If Brevo cannot send, the caller refuses the flow outside DEBUG
instead of leaving an account that can never be verified.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from apps.accounts.models import EmailChallengePurpose, OneTimePassword, User
from apps.common.exceptions import AuthenticationError, ErrorCode, RequestError

INVALID_CODE = "Invalid or expired code"
CODE_DIGITS = 6


def _generate_code() -> str:
    return f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"


def _normalize_otp(otp: int | str) -> str:
    """An OTP crosses the wire as a JSON number, which drops leading zeros.

    A code of "004321" arrives as 4321. Pad it back before comparing, or one
    code in ten can never be verified.
    """
    raw = str(otp).strip()
    if raw.isdigit() and len(raw) < CODE_DIGITS:
        return raw.zfill(CODE_DIGITS)
    return raw


async def issue(
    *,
    user: User,
    email: str,
    purpose: EmailChallengePurpose,
    subject: str,
    body: str,
) -> None:
    """Store a fresh challenge and email it. ``body`` may use ``{code}``."""
    from apps.common.email.brevo import send as brevo_send
    from asgiref.sync import sync_to_async

    code = _generate_code()
    now = timezone.now()
    await OneTimePassword.objects.aupdate_or_create(
        user=user,
        defaults={
            "code": code,
            "purpose": purpose,
            "email": email,
            "created_at": now,
            "expires_at": now + timedelta(minutes=settings.EMAIL_CODE_TTL_MINUTES),
            "attempts": 0,
        },
    )

    delivered = await sync_to_async(brevo_send, thread_sensitive=False)(
        to=email,
        subject=subject,
        text=body.format(code=code),
    )
    if not delivered and not settings.DEBUG:
        await OneTimePassword.objects.filter(user=user, purpose=purpose).adelete()
        raise RequestError(
            ErrorCode.EMAIL_DELIVERY_UNAVAILABLE,
            "Email delivery is not configured on this server; "
            "email verification cannot complete yet.",
            503,
        )


async def consume(
    *,
    user: User,
    purpose: EmailChallengePurpose,
    otp: int,
    email: str | None = None,
) -> None:
    """Validate and burn a challenge. Raises on any mismatch or expired state."""
    record = await OneTimePassword.objects.filter(user=user, purpose=purpose).afirst()
    if record is None:
        raise AuthenticationError(INVALID_CODE)
    if email is not None and record.email != email:
        raise AuthenticationError(INVALID_CODE)
    if record.expires_at is None or timezone.now() > record.expires_at:
        raise AuthenticationError(INVALID_CODE)
    if record.attempts >= settings.EMAIL_CODE_MAX_ATTEMPTS:
        raise AuthenticationError(INVALID_CODE)
    if not secrets.compare_digest(record.code, _normalize_otp(otp)):
        record.attempts += 1
        await record.asave(update_fields=["attempts"])
        raise AuthenticationError(INVALID_CODE)

    await record.adelete()
