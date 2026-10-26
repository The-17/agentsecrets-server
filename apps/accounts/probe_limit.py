"""IP-keyed throttling for the public account-probe endpoint.

The auth UI asks the server "does this email have an account" before it shows
the password step. That is account enumeration by design, so it must be paced:
without a limit one caller can walk a leaked email list and learn which ones
exist, which is exactly what a login-attempt limiter is meant to prevent.

No Redis in this deployment, so the counter lives in Postgres. Each probe writes
one row and the count is a windowed query, which is the same shape the OPAQUE
challenge limiter already uses.
"""

import hashlib
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.common.exceptions import RateLimitError

# Generous enough for a person retyping an email, tight enough that walking a
# list is impractical. Per IP, not per account.
PROBE_WINDOW = timedelta(minutes=15)
MAX_PROBES_PER_WINDOW = 30

# Old rows are pruned opportunistically, so the table stays small without a
# cron job or a management command.
RETENTION = timedelta(days=1)


def client_ip(request) -> str:
    """The caller's address, honouring the proxy header Vercel sets.

    X-Forwarded-For is a client-supplied list in general, but behind a trusted
    edge the left-most entry is the real peer. The limit is per-IP best effort:
    a spoofed header costs the attacker their own quota, not someone else's.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "unknown")


def _ip_key(ip: str) -> str:
    # Never store raw addresses: the probe table would become a log of who
    # checked which address, which is worse than the enumeration itself.
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()


def enforce_probe_limit(request) -> None:
    """Count one probe for this caller, or raise RateLimitError."""
    from .models import AccountProbe

    now = timezone.now()
    key = _ip_key(client_ip(request))

    with transaction.atomic():
        AccountProbe.objects.filter(created_at__lt=now - RETENTION).delete()
        recent = AccountProbe.objects.filter(
            ip_hash=key, created_at__gte=now - PROBE_WINDOW
        ).count()
        if recent >= MAX_PROBES_PER_WINDOW:
            raise RateLimitError("Too many attempts. Try again in a few minutes.")
        AccountProbe.objects.create(ip_hash=key)
