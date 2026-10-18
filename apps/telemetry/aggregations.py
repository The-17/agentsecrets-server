"""Cross-cutting telemetry aggregations.

Tier-3 forensic rows are the source of truth for cloud-resolver behaviour: each
row carries the real decision and the number of secret handles in scope.
Tier-2 audit rows cannot separate a blocked call from a redaction, because the
resolver writes blocked calls with ``redacted=True`` as well. Counting audit
rows therefore overstated redactions and produced no block count at all.
"""

from datetime import date
from typing import Dict, Optional

from django.db.models import Count, IntegerField, Sum
from django.db.models.fields.json import KeyTextTransform
from django.db.models.functions import Cast

from apps.workspaces.models import AuditLogEntry, ForensicAuditLogEntry


def cloud_call_stats(*, until_date: Optional[date] = None) -> Dict[str, int]:
    """Resolver call count and wall-clock duration, from Tier-2 audit rows.

    Duration comes from ``duration_ms`` (the resolver's own measurement).
    ``proxy_duration_ms`` is never populated by the resolver, so summing it
    always produced zero.
    """
    qs = AuditLogEntry.objects.filter(resolution_path="direct_resolve")
    if until_date is not None:
        qs = qs.filter(timestamp__date__lte=until_date)
    agg = qs.aggregate(calls=Count("id"), duration_ms=Sum("duration_ms"))
    return {"calls": agg["calls"] or 0, "duration_ms": agg["duration_ms"] or 0}


def cloud_resolution_stats(*, until_date: Optional[date] = None) -> Dict[str, int]:
    """Decision-level cloud counters, from the Tier-3 forensic twin.

    ``blocked`` counts rows the resolver refused (capability, allowlist,
    secret policy, SSRF). ``redacted`` counts permitted rows that actually
    scrubbed a credential echo. ``secrets_resolved`` counts the secret handles
    injected by permitted calls — a call that injected nothing resolves zero
    secrets, and a call that injected three resolves three.
    """
    qs = ForensicAuditLogEntry.objects.all()
    if until_date is not None:
        qs = qs.filter(created_at__date__lte=until_date)

    permitted = qs.filter(enforcement_json__decision="permitted")
    secrets_total = (
        permitted.aggregate(
            total=Sum(
                Cast(
                    KeyTextTransform("secrets_count", "snapshot_json"),
                    IntegerField(),
                )
            )
        )["total"]
        or 0
    )
    return {
        "blocked": qs.filter(enforcement_json__decision="blocked").count(),
        "redacted": permitted.filter(resolution_json__redaction_triggered=True).count(),
        "secrets_resolved": secrets_total,
    }