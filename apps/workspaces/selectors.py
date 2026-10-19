from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import timedelta
from typing import Any
from django.conf import settings
from django.core.cache import cache
from django.db.models import Count, Max, Q, Subquery, OuterRef, IntegerField
from django.db.models.functions import Coalesce
from django.utils import timezone
from asgiref.sync import sync_to_async

from apps.accounts.models import User
from apps.common.exceptions import (
    NotFoundError,
    AuthorizationError,
    BodyValidationError,
)
from .models import (
    Workspace,
    WorkspaceTier,
    Membership,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
    WorkspaceAllowlistLog,
    AgentRegistration,
    AgentToken,
    AuditLogEntry,
    IdentityLevel,
    WorkspaceActivityLog,
    ForensicAuditLogEntry,
)
from .billing_source import plan_is_pro, resolver_plan

logger = logging.getLogger("apps.workspaces")


def _report_usage_async(*, raw_token: str, billing_id: str, workspace_id: str, environment: str) -> None:
    """Fire-and-forget usage report to the cloud resolver.

    The resolver verifies the raw workload token itself and debits the account
    its own store associates with that token. The server asserts no entitlement,
    so a self-hosted or compromised server cannot grant quota by calling this.
    Failures are logged and never affect secret delivery.
    """
    if not getattr(settings, "RESOLVER_URL", ""):
        return

    async def _post():
        loop = asyncio.get_running_loop()

        def _send():
            import urllib.request
            req = urllib.request.Request(
                settings.RESOLVER_URL.rstrip("/") + "/v1/billing/record-usage",
                data=json.dumps({"count": 1}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-AS-Agent-Token": raw_token},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status

        try:
            await asyncio.wait_for(loop.run_in_executor(None, _send), timeout=6)
        except Exception as exc:  # never surface to the caller
            logger.warning(
                "USAGE_REPORT_FAILED: failed to report env resolution usage for workspace %s (%s): %s",
                workspace_id, billing_id, exc,
            )

    try:
        task = asyncio.create_task(_post())
    except RuntimeError:
        return  # no running event loop; skip the advisory report

    # Keep a reference so the task isn't garbage-collected mid-flight.
    _REPORT_TASKS.add(task)
    task.add_done_callback(_REPORT_TASKS.discard)


_REPORT_TASKS: set[asyncio.Task] = set()



class WorkspaceSelector:
    """
    Pure read-only query selector layer for Workspaces and Memberships.
    """

    @staticmethod
    async def get_membership(*, user: User, workspace_id: uuid.UUID) -> Membership:
        member = await Membership.objects.filter(
            user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE
        ).select_related("workspace", "workspace__owner").afirst()
        if not member:
            raise NotFoundError("Workspace not found or you don't have access")
        return member

    @staticmethod
    async def check_admin(*, user: User, workspace_id: uuid.UUID) -> Membership:
        member = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if member.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only admins and owners can perform this action")
        return member

    @staticmethod
    async def list_user_workspaces(*, user: User) -> list[dict[str, Any]]:
        memberships = Membership.objects.filter(
            user=user, status=MembershipStatus.ACTIVE
        ).values(
            "role",
            "encrypted_workspace_key",
            "workspace__id",
            "workspace__name",
            "workspace__type",
            "workspace__tier",
            "workspace__billing_id",
            "workspace__owner__billing_id",
            "workspace__created_at",
        )
        return [
            {
                "id": str(m["workspace__id"]),
                "name": m["workspace__name"],
                "type": m["workspace__type"],
                "tier": m.get("workspace__tier") or "free",
                "role": m["role"],
                "billing_id": (m["workspace__billing_id"] if m.get("workspace__tier") == "pro" else None) or m["workspace__owner__billing_id"],
                "encrypted_workspace_key": m["encrypted_workspace_key"],
                "created_at": m["workspace__created_at"].isoformat() if m["workspace__created_at"] else None,
            }
            async for m in memberships
        ]

    @staticmethod
    async def list_workspace_members(*, workspace_id: uuid.UUID) -> list[dict[str, Any]]:
        memberships = Membership.objects.filter(workspace_id=workspace_id).values(
            "id",
            "user_id",
            "user__email",
            "user__first_name",
            "user__last_name",
            "role",
            "status",
            "created_at",
        )
        return [
            {
                "id": str(m["id"]),
                "user_id": str(m["user_id"]),
                "email": m["user__email"],
                "name": f"{m['user__first_name']} {m['user__last_name']}",
                "role": m["role"],
                "status": m["status"],
                "created_at": m["created_at"].isoformat() if m["created_at"] else None,
            }
            async for m in memberships
        ]


class AllowlistSelector:
    """
    Pure read-only query selector layer for Workspace Allowlists and Logs.
    """

    @staticmethod
    async def list_allowlist(*, workspace_id: uuid.UUID) -> list[dict[str, Any]]:
        data: list[dict[str, Any]] = []
        async for e in WorkspaceAllowlist.objects.filter(workspace_id=workspace_id).select_related("added_by"):
            data.append({
                "id": str(e.id),
                "domain": e.domain,
                "added_by_email": e.added_by.email if e.added_by else None,
                "added_at": e.added_at.isoformat() if e.added_at else None,
            })
        return data

    @staticmethod
    async def list_allowlist_logs(*, workspace_id: uuid.UUID) -> list[dict[str, Any]]:
        data: list[dict[str, Any]] = []
        async for log in WorkspaceAllowlistLog.objects.filter(workspace_id=workspace_id).select_related("performed_by"):
            data.append({
                "domain": log.domain,
                "action": log.action,
                "performed_by_email": log.performed_by.email if log.performed_by else None,
                "performed_at": log.performed_at.isoformat() if log.performed_at else None,
            })
        return data


class AgentSelector:
    """
    Pure read-only query selector layer for AI Agents and Agent Tokens.
    """

    @staticmethod
    def serialize_agent(agent: AgentRegistration) -> dict[str, Any]:
        last_used = getattr(agent, "last_used_at", None)
        return {
            "id": str(agent.id),
            "name": agent.name,
            "project_id": str(agent.project_id) if agent.project_id else None,
            "token_count": getattr(agent, "token_count", 0),
            "active_token_count": getattr(agent, "active_token_count", 0),
            "last_used_at": last_used.isoformat() if last_used else None,
            "created_at": agent.created_at.isoformat(),
            "capabilities": agent.capabilities or {},
        }

    @staticmethod
    def _agent_subqueries():
        token_count_sub = Coalesce(
            Subquery(
                AgentToken.objects.filter(registration=OuterRef("pk"))
                .values("registration")
                .annotate(cnt=Count("pk"))
                .values("cnt"),
                output_field=IntegerField(),
            ),
            0,
        )
        active_token_count_sub = Coalesce(
            Subquery(
                AgentToken.objects.filter(registration=OuterRef("pk"), revoked_at__isnull=True)
                .values("registration")
                .annotate(cnt=Count("pk"))
                .values("cnt"),
                output_field=IntegerField(),
            ),
            0,
        )
        last_used_at_sub = Subquery(
            AgentToken.objects.filter(registration=OuterRef("pk"))
            .values("registration")
            .annotate(max_used=Max("last_used_at"))
            .values("max_used")
        )
        return token_count_sub, active_token_count_sub, last_used_at_sub

    @staticmethod
    async def list_agents(
        *,
        workspace_id: uuid.UUID,
        project_id: uuid.UUID | None = None,
        include_projects: bool = False,
    ) -> list[dict[str, Any]]:
        qs = AgentRegistration.objects.filter(workspace_id=workspace_id)
        if project_id:
            qs = qs.filter(project_id=project_id)
        elif not include_projects:
            qs = qs.filter(project__isnull=True)

        token_cnt, active_cnt, last_used = AgentSelector._agent_subqueries()
        agents: list[dict[str, Any]] = []
        async for a in qs.annotate(
            token_count=token_cnt,
            active_token_count=active_cnt,
            last_used_at=last_used,
        ):
            agents.append(AgentSelector.serialize_agent(a))
        return agents

    @staticmethod
    async def get_agent_by_id(*, workspace_id: uuid.UUID, registration_id: str) -> dict[str, Any]:
        token_cnt, active_cnt, last_used = AgentSelector._agent_subqueries()
        agent = await AgentRegistration.objects.filter(
            id=registration_id, workspace_id=workspace_id
        ).annotate(
            token_count=token_cnt,
            active_token_count=active_cnt,
            last_used_at=last_used,
        ).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        return AgentSelector.serialize_agent(agent)

    @staticmethod
    async def get_agent_capabilities(*, workspace_id: uuid.UUID, registration_id: str) -> dict[str, Any]:
        agent = await AgentRegistration.objects.filter(
            id=registration_id, workspace_id=workspace_id
        ).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        return agent.capabilities or {}

    @staticmethod
    async def list_agent_tokens(*, workspace_id: uuid.UUID, registration_id: str) -> list[dict[str, Any]]:
        exists = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).aexists()
        if not exists:
            raise NotFoundError("Agent not found")

        now = timezone.now()
        data: list[dict[str, Any]] = []
        async for t in AgentToken.objects.filter(registration_id=registration_id):
            if t.revoked_at or t.rotation_state == "revoked":
                status = "revoked"
            elif t.rotation_state == "superseded":
                status = "superseded_overlap" if (t.overlap_until and t.overlap_until >= now) else "overlap_expired"
            elif t.expires_at and t.expires_at < now:
                status = "expired"
            else:
                status = "active"
            data.append({
                "id": str(t.id),
                "label": t.label,
                "environment": getattr(t, "environment", None) or "",
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
                "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
                "created_at": t.created_at.isoformat(),
                "status": status,
                "rotation_state": t.rotation_state,
                "rotation_family_id": t.rotation_family_id,
                "overlap_until": t.overlap_until.isoformat() if t.overlap_until else None,
                "next_rotation_at": t.next_rotation_at.isoformat() if t.next_rotation_at else None,
                "rotation_period_days": t.rotation_period.days if t.rotation_period else None,
                "superseded_by": t.superseded_by,
            })
        return data

    @staticmethod
    async def list_revoked_token_ids(*, workspace_id: uuid.UUID) -> list[str]:
        """List all revoked and expired superseded token IDs for a workspace."""
        now = timezone.now()
        qs = AgentToken.objects.filter(
            workspace_id=workspace_id
        ).filter(
            Q(revoked_at__isnull=False)
            | Q(rotation_state="revoked")
            | (Q(rotation_state="superseded") & (Q(overlap_until__isnull=True) | Q(overlap_until__lt=now)))
        ).values_list("id", flat=True)
        return [str(token_id) async for token_id in qs]

    @staticmethod
    async def get_due_token_rotations(*, workspace_id: uuid.UUID) -> list[dict[str, Any]]:
        """Rotation-armed families past their cadence (metadata only, never
        secret material). Consumed by the resolver's Pro-gated sweep (HR-M3)."""
        now = timezone.now()
        due: list[dict[str, Any]] = []
        qs = AgentToken.objects.filter(
            workspace_id=workspace_id,
            rotation_state="active",
            revoked_at__isnull=True,
            rotation_period__isnull=False,
            next_rotation_at__lte=now,
        ).only(
            "id", "workspace_id", "registration_id", "rotation_family_id",
            "rotation_period", "next_rotation_at", "rotation_state",
        )
        async for t in qs:
            due.append({
                "family_key": t.rotation_family_id or str(t.id),
                "token_id": str(t.id),
                "workspace_id": str(t.workspace_id),
                "registration_id": str(t.registration_id),
                "next_rotation_at": t.next_rotation_at.isoformat() if t.next_rotation_at else None,
                "rotation_period_days": t.rotation_period.days if t.rotation_period else None,
                "rotation_state": t.rotation_state,
            })
        return due


def cloud_source_q() -> Q:
    """Rows that read as cloud-origin anywhere the dashboard counts them.

    ``list_audit_logs`` coerces a missing or empty ``source`` to ``cloud`` at
    read time (``log.get("source") or "cloud"``), so the summary's cloud
    bucket and the ``source=cloud`` filter must coerce identically — otherwise
    the card contradicts the Origin column over the very same rows. One
    predicate, used by every read path, is what keeps them equal.
    """
    return Q(source="cloud") | Q(source="") | Q(source__isnull=True)


class AuditSelector:
    """
    Pure read-only query selector layer for Audit Logs.
    """

    # Plan-mode log retention windows. Free keeps 3 days; Pro keeps 30.
    # Unknown tier fails open (no restriction).
    FREE_RETENTION_DAYS = 3
    PRO_RETENTION_DAYS = 30

    SUMMARY_CACHE_TTL = 60
    # Long enough that a version bump can never collide with an entry cached
    # under the previous version; summaries themselves expire after 60s.
    SUMMARY_VERSION_TTL = 7 * 24 * 3600

    @staticmethod
    def summary_version(workspace_id: str) -> int:
        return cache.get(f"audit-summary:ver:{workspace_id}") or 1

    @staticmethod
    def invalidate_summary_cache(workspace_id) -> None:
        """Version-bump every cached summary for this workspace.

        Called wherever audit rows are written. The list reads the database
        live while the summary serves a 60s cache, so without this the card
        silently lags the table exactly when new events are landing — the
        dashboard showed eight rows beside a card saying five.
        """
        key = f"audit-summary:ver:{workspace_id}"
        try:
            cache.incr(key)
        except ValueError:
            cache.set(key, 2, AuditSelector.SUMMARY_VERSION_TTL)

    @staticmethod
    async def retention_window(*, workspace_id: str) -> tuple[int | None, bool]:
        """(days, restricted) for a workspace. restricted=False means pro/unknown.

        The resolver owns entitlement, so a cache miss confirms the local mirror
        against the resolver before clamping a Free workspace. Without that, an
        upgrade stayed clamped to 3 days until someone called the billing
        reconcile endpoint by hand. A resolver miss falls back to the mirror and
        re-checks after 60s instead of 5 minutes.
        """
        try:
            cache_key = f"ws-tier:{workspace_id}"
            tier = await sync_to_async(cache.get)(cache_key)
            if tier is None:
                ws = await Workspace.objects.filter(id=workspace_id).select_related("owner").afirst()
                if ws is None:
                    return None, False
                db_tier = getattr(ws, "tier", None)
                if db_tier == WorkspaceTier.PRO:
                    # Only a resolver-confirmed reconcile can set the mirror to
                    # Pro, so trust it. Confirm the other direction: a Free
                    # mirror may be a paid workspace whose upgrade has not been
                    # reconciled yet, and clamping it would be wrong.
                    tier = db_tier
                    ttl = 300
                else:
                    payload = await resolver_plan(billing_id=ws.effective_billing_id)
                    if payload is None:
                        tier = db_tier or "unknown"
                        ttl = 60
                    else:
                        tier = WorkspaceTier.PRO if plan_is_pro(payload) else WorkspaceTier.FREE
                        ttl = 300
                await sync_to_async(cache.set)(cache_key, tier, ttl)
        except Exception:
            return None, False
        if tier == WorkspaceTier.PRO:
            return AuditSelector.PRO_RETENTION_DAYS, False
        if tier == WorkspaceTier.FREE:
            return AuditSelector.FREE_RETENTION_DAYS, True
        return None, False

    @staticmethod
    async def apply_retention_floor(qs, *, workspace_id: str, field: str = "timestamp"):
        """Clamp a log queryset to the workspace's plan retention window.

        Shared by every Tier-1/Tier-2/Tier-3 read so the billing promise (Free
        3 days, Pro 30) has one implementation. ``field`` names the timestamp
        column: audit rows carry ``timestamp``, activity rows ``created_at``.
        """
        days, _ = await AuditSelector.retention_window(workspace_id=str(workspace_id))
        if days:
            qs = qs.filter(**{f"{field}__gte": timezone.now() - timedelta(days=days)})
        return qs

    @staticmethod
    def apply_filters(qs, params: dict[str, Any]):
        simple = {
            "project_id": "project_id",
            "agent_id": "agent_id",
            "agent_token_id": "agent_token_id",
            "identity_level": "identity_level",
            "credential_ref": "credential_ref",
            "environment": "environment",
        }
        for param, field in simple.items():
            val = params.get(param)
            if val:
                qs = qs.filter(**{field: val})
        # source is not a plain equality: the table's Origin column reads an
        # empty/missing source as cloud, so filtering to Cloud has to select
        # the same rows the reader already sees marked cloud.
        source = params.get("source")
        if source == "cloud":
            qs = qs.filter(cloud_source_q())
        elif source:
            qs = qs.filter(source=source)
        resolution_path = params.get("resolution_path")
        if resolution_path:
            # Comma-separated allowed (e.g. ?resolution_path=env,direct_resolve).
            values = [v.strip() for v in str(resolution_path).split(",") if v.strip()]
            if len(values) > 1:
                qs = qs.filter(resolution_path__in=values)
            elif values:
                qs = qs.filter(resolution_path=values[0])
        exclude_resolution = params.get("exclude_resolution_path")
        if exclude_resolution:
            qs = qs.exclude(resolution_path=exclude_resolution)
        domain = params.get("domain")
        if domain:
            qs = qs.filter(target_domain__icontains=domain)
        method = params.get("method")
        if method:
            qs = qs.filter(method=method.upper())
        status_code = params.get("status_code")
        if status_code:
            qs = qs.filter(status_code=status_code)
        since = params.get("since")
        if since:
            qs = qs.filter(timestamp__gte=since)
        until = params.get("until")
        if until:
            qs = qs.filter(timestamp__lte=until)
        return qs

    @staticmethod
    async def list_audit_logs(*, workspace_id: str, params: dict[str, Any], limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        qs = AuditSelector.apply_filters(
            AuditLogEntry.objects.filter(workspace_id=workspace_id).exclude(identity_level=IdentityLevel.USER),
            params,
        )
        qs = await AuditSelector.apply_retention_floor(qs, workspace_id=workspace_id)
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)
        fields = [
            "id",
            "timestamp",
            "agent_id",
            "identity_level",
            "credential_ref",
            "injection_style",
            "target_domain",
            "target_url",
            "method",
            "status_code",
            "duration_ms",
            "redacted",
            "resolution_path",
            "error",
            "source",
        ]
        logs = qs.order_by("-timestamp", "-id").values(*fields)[offset : offset + limit]
        return [
            {
                "id": str(log["id"]),
                "timestamp": log["timestamp"].isoformat() if log["timestamp"] else None,
                "agent_id": log["agent_id"],
                "identity_level": log["identity_level"],
                "credential_ref": log["credential_ref"],
                "injection_style": log["injection_style"],
                "target_domain": log["target_domain"],
                "target_url": log["target_url"],
                "method": log["method"],
                "status_code": log["status_code"],
                "duration_ms": log["duration_ms"],
                "redacted": log["redacted"],
                "resolution_path": log["resolution_path"],
                # error is a JSONField: structured enforcement blocks land here
                # (e.g. {'decision': 'blocked', ...}). Coerce to a JSON string
                # so one structured row can never 500 the whole list — same
                # convention as the export path below.
                "error": log["error"] if isinstance(log["error"], (str, type(None))) else json.dumps(log["error"], default=str),
                "source": log.get("source") or "cloud",
            }
            async for log in logs
        ]

    @staticmethod
    async def get_audit_log_detail(*, log_id: str, user: User) -> dict[str, Any]:
        log = await AuditLogEntry.objects.filter(
            id=log_id
        ).exclude(identity_level=IdentityLevel.USER).afirst()
        if not log:
            raise NotFoundError("Log not found")
        await WorkspaceSelector.get_membership(user=user, workspace_id=log.workspace_id)
        fields: dict[str, Any] = {}
        for f in log._meta.get_fields():
            if hasattr(f, "attname"):
                val = getattr(log, f.attname)
                if hasattr(val, "isoformat"):
                    val = val.isoformat()
                elif not isinstance(val, (str, int, float, bool, type(None))):
                    val = str(val)
                fields[f.attname] = val
        return fields

    @staticmethod
    async def get_replay_by_audit(*, log_id: str, user: User) -> dict[str, Any]:
        """Resolve a Tier-3 forensic replay from a Tier-2 audit id.

        Primary path is the resolver-emitted correlation_id stored on both
        rows. Pre-linkage rows fall back to timestamp proximity (±2s within
        the workspace), scoped to the audit row's own event type so an env
        delivery can never resolve to an unrelated proxy decision.
        Raises NotFoundError when no forensic twin exists (e.g. CLI-origin
        events, whose forensic chain lives only in local SQLite).
        """
        log = await AuditLogEntry.objects.filter(
            id=log_id
        ).exclude(identity_level=IdentityLevel.USER).afirst()
        if not log:
            raise NotFoundError("Log not found")
        await WorkspaceSelector.get_membership(user=user, workspace_id=log.workspace_id)

        forensic = None
        if log.correlation_id:
            forensic = await ForensicAuditLogEntry.objects.filter(
                workspace_id=log.workspace_id,
                correlation_id=log.correlation_id,
            ).afirst()
        if forensic is None and log.timestamp:
            # Proximity fallback is only for genuine pre-linkage rows (emitted
            # before correlation_id existed). Scope it to the event type the
            # audit row actually is, so an env delivery can never bind to an
            # unrelated proxy resolve that landed within ±2s in the same
            # workspace and replay the wrong decision.
            expected_type = "env_delivery" if (log.resolution_path or "") == "env" else "proxy_call"
            window_start = log.timestamp - timedelta(seconds=2)
            window_end = log.timestamp + timedelta(seconds=2)
            forensic = await ForensicAuditLogEntry.objects.filter(
                workspace_id=log.workspace_id,
                created_at__gte=window_start,
                created_at__lte=window_end,
                event_json__type=expected_type,
            ).order_by("created_at").afirst()
        if forensic is None:
            raise NotFoundError("No forensic record for this event")
        return await ForensicLogSelector.get_replay(log_id=forensic.id, user=user)

    @staticmethod
    async def get_audit_log_summary(
        *,
        workspace_id: str,
        params: dict[str, Any] | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        """Aggregate the telemetry stream under the same filters as the list.

        The dashboard shows these numbers next to a filtered table, so the
        summary has to accept the list's query params; otherwise the cards
        describe a different set of rows than the reader is looking at. Scope
        is the plan retention window, never an arbitrary month boundary.
        """
        params = dict(params or {})
        start = start or params.get("start") or None
        end = end or params.get("end") or None

        # 60s cache-aside: dashboard polls summary on every navigation +
        # visibility return. Aggregates only — no secret material is cached.
        # The version segment is bumped by invalidate_summary_cache on every
        # audit write, so a landing row makes every cached count unreachable
        # instead of letting the card contradict a live list for a minute.
        fingerprint = "&".join(f"{k}={params[k]}" for k in sorted(params))
        cache_key = (
            f"audit-summary:{workspace_id}:v{AuditSelector.summary_version(workspace_id)}:"
            f"{start or 'all'}:{end or 'all'}:{fingerprint}"
        )
        cached = await sync_to_async(cache.get)(cache_key)
        if cached is not None:
            return cached

        qs = AuditLogEntry.objects.filter(workspace_id=workspace_id).exclude(identity_level=IdentityLevel.USER)
        qs = AuditSelector.apply_filters(qs, params)
        if start:
            qs = qs.filter(timestamp__gte=start)
        if end:
            qs = qs.filter(timestamp__lte=end)
        qs = await AuditSelector.apply_retention_floor(qs, workspace_id=workspace_id)
        retention_days, retention_restricted = await AuditSelector.retention_window(workspace_id=str(workspace_id))

        # Same "failed" predicate the per-agent and per-domain breakdowns use, so
        # the card and the breakdown can never disagree.
        failed_q = Q(status_code__gte=400) | Q(error__isnull=False)

        # Single aggregate for totals instead of 3 separate COUNT scans.
        totals = await qs.aaggregate(
            total=Count("id"),
            errors=Count("id", filter=Q(status_code__gte=400)),
            failed=Count("id", filter=failed_q),
            redacted=Count("id", filter=Q(redacted=True)),
            cloud=Count("id", filter=cloud_source_q()),
            cli=Count("id", filter=Q(source="cli")),
            env=Count("id", filter=Q(resolution_path="env")),
            anon=Count("id", filter=Q(identity_level=IdentityLevel.ANONYMOUS)),
        )
        total_requests = totals["total"] or 0
        total_errors = totals["errors"] or 0
        failed = totals["failed"] or 0

        by_agent = await sync_to_async(list)(
            qs.exclude(agent_id__isnull=True).exclude(agent_id="").values("agent_id").annotate(
                count=Count("id"),
                failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
            ).order_by("-count")[:50]
        )
        by_domain = await sync_to_async(list)(
            qs.values("target_domain").annotate(
                count=Count("id"),
                failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
            ).order_by("-count")[:50]
        )
        by_credential = await sync_to_async(list)(
            qs.values("credential_ref").annotate(
                count=Count("id"),
                failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
            ).order_by("-count")[:50]
        )
        anon_count = totals["anon"] or 0

        result = {
            "period": {"start": start or "all", "end": end or "all"},
            "totals": {"requests": total_requests, "errors": total_errors},
            # Counts the dashboard cards read. `blocked` uses the breakdown's
            # failed predicate; `ok` is its complement over the same set.
            "ok": max(0, total_requests - failed),
            "blocked": failed,
            "redacted": totals["redacted"] or 0,
            # Quota meters cloud activity only: the resolver debits cloud proxy
            # resolutions (TryConsumeUsage) and the control plane reports
            # cloud-backed env deliveries (/v1/billing/record-usage). Local CLI
            # calls reach neither path, so the dashboard must not add them in.
            "cloud_requests": totals["cloud"] or 0,
            "cli_requests": totals["cli"] or 0,
            "env_requests": totals["env"] or 0,
            "by_agent": [{"agent_id": r["agent_id"], "count": r["count"], "failed": r["failed"]} for r in by_agent],
            "by_credential": [{"credential_ref": r["credential_ref"], "count": r["count"], "failed": r["failed"]} for r in by_credential],
            "by_domain": [{"domain": r["target_domain"], "count": r["count"], "failed": r["failed"]} for r in by_domain],
            "anonymous_call_count": anon_count,
            "retention": {"days": retention_days, "restricted": retention_restricted},
        }
        await sync_to_async(cache.set)(cache_key, result, AuditSelector.SUMMARY_CACHE_TTL)
        return result


class CloudDelegationSelector:
    """Selector for Cloud Resolver CEDK delegations."""

    @staticmethod
    async def get_delegation_info(*, user: User, workspace_id: uuid.UUID) -> dict[str, Any]:
        member = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        from .models import CloudDelegationKey
        delegation = await CloudDelegationKey.objects.filter(workspace_id=workspace_id, is_active=True).afirst()

        return {
            "workspace_id": str(workspace_id),
            "resolver_name": delegation.resolver_name if delegation else "default",
            "public_key": delegation.public_key if delegation else None,
            "has_sealed_key": bool(delegation and delegation.sealed_workspace_key),
            "is_active": delegation.is_active if delegation else False,
            "user_encrypted_workspace_key": member.encrypted_workspace_key,
        }

    @staticmethod
    async def get_resolver_delegation(*, workspace_id: uuid.UUID) -> dict[str, Any]:
        """Active CEDK delegation for resolver-identity callers (B2 DEK sync).

        Returns the sealed blob and public key only — no user material, no
        membership lookup. The resolver unseals with its own CEDK_priv."""
        from .models import CloudDelegationKey
        delegation = await CloudDelegationKey.objects.filter(
            workspace_id=workspace_id, is_active=True
        ).afirst()
        return {
            "workspace_id": str(workspace_id),
            "sealed_workspace_key": delegation.sealed_workspace_key if delegation else None,
            "public_key": delegation.public_key if delegation else None,
            "has_delegation": bool(delegation and delegation.sealed_workspace_key),
        }


class WorkloadSelector:
    """Selector for headless container workload secret deliveries."""

    @staticmethod
    async def resolve_env_attribution(*, raw_token: str) -> dict[str, Any] | None:
        """Best-effort workspace attribution for a refused env delivery.

        resolve_env_payload validates the token strictly (unrevoked, unexpired,
        capability granted, project contained). A refusal must still be
        attributable to a workspace so the failure is auditable, so this looks up
        the registration WITHOUT those gates. Returns None when no token matches
        at all, in which case there is no tenant to file the refusal against."""
        import hashlib
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        token = await AgentToken.objects.select_related(
            "registration",
            "registration__workspace",
        ).filter(token_hash=token_hash).order_by("-created_at").afirst()
        if not token or not token.registration or not token.registration.workspace_id:
            return None
        registration = token.registration
        workspace = registration.workspace
        environment = (
            getattr(token, "environment", None)
            or getattr(registration, "environment", None)
            or "production"
        )
        allowlist = [
            d
            async for d in WorkspaceAllowlist.objects.filter(
                workspace_id=registration.workspace_id
            ).values_list("domain", flat=True)
        ]
        return {
            "workspace_id": str(registration.workspace_id),
            "workspace_name": workspace.name if workspace else "",
            "agent_name": registration.name,
            "project_id": str(registration.project_id) if registration.project_id else None,
            "token_id": str(token.id),
            "environment": environment,
            "allowlist": allowlist,
        }

    @staticmethod
    async def resolve_env_payload(*, raw_token: str, env_override: str | None = None) -> dict[str, Any]:
        import hashlib
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        token = await AgentToken.objects.select_related(
            "registration",
            "registration__workspace",
            "registration__workspace__owner"
        ).filter(
            token_hash=token_hash,
            revoked_at__isnull=True,
        ).afirst()

        if not token:
            raise AuthorizationError("Invalid or revoked workload token")

        if token.expires_at and token.expires_at < timezone.now():
            raise AuthorizationError("Workload token has expired")

        registration = token.registration
        workspace = registration.workspace

        # Least privilege: env delivery returns REAL credentials, so it requires an
        # explicit can_env_read grant. Absent/false → refuse. This is the server's
        # authoritative gate; the resolver mirrors the same default on its side.
        caps = registration.capabilities or {}
        can_env_read = caps.get("can_env_read", False)
        if can_env_read is not True and can_env_read not in ("true", "1", "yes"):
            raise AuthorizationError("Workload token lacks can_env_read capability; environment delivery is not permitted")

        env_name = env_override or getattr(token, "environment", None) or getattr(registration, "environment", None) or "production"

        # Best-effort usage reporting ONLY — the server is not a billing authority.
        # The cloud resolver verifies the raw workload token itself and debits the
        # matching account from its own store; it ignores whatever this server
        # asserts. A self-hosted server therefore cannot grant or inflate anything.
        # This report is fire-and-forget: it never blocks, gates, or fails secret
        # delivery, and network errors are logged, not interpreted as a quota grant.
        billing_id = getattr(workspace, "effective_billing_id", None) if workspace else None
        if billing_id:
            _report_usage_async(
                raw_token=raw_token,
                billing_id=billing_id,
                workspace_id=str(workspace.id),
                environment=env_name,
            )

        # Query secrets for this project & environment
        from apps.secrets_app.models import Project, Secret
        from apps.common.services.encryption import EncryptionService

        # Cross-workspace containment, fail closed, mirroring
        # AgentService.verify_agent_token: a project-scoped agent may only read a
        # project that lives in the token's own workspace.
        if registration.project_id:
            project_workspace_id = await Project.objects.filter(
                id=registration.project_id
            ).values_list("workspace_id", flat=True).afirst()
            if project_workspace_id is None or str(project_workspace_id) != str(workspace.id):
                logger.warning(
                    "ENV_RESOLVE_WORKSPACE_MISMATCH: token=%s workspace=%s project=%s project_ws=%s",
                    token.id,
                    workspace.id,
                    registration.project_id,
                    project_workspace_id,
                )
                raise AuthorizationError("Agent project does not belong to the token's workspace")

        # Always scope by the token's workspace, even when a project_id is set, so
        # a dangling or cross-workspace project reference can never widen the
        # query beyond the workspace the token belongs to.
        filter_kwargs = {"environment": env_name, "project__workspace_id": workspace.id}
        if registration.project_id:
            filter_kwargs["project_id"] = registration.project_id

        secrets_qs = Secret.objects.filter(**filter_kwargs).values("key", "value")

        secrets_map = {}
        async for s in secrets_qs:
            try:
                secrets_map[s["key"]] = EncryptionService.decrypt(s["value"])
            except Exception:
                secrets_map[s["key"]] = s["value"]

        # Query active domain allowlist for this workspace
        allowlist_qs = WorkspaceAllowlist.objects.filter(
            workspace_id=workspace.id,
        ).values_list("domain", flat=True)

        allowlist = [d async for d in allowlist_qs]

        return {
            "workspace_id": str(workspace.id),
            "workspace_name": workspace.name,
            "agent_name": registration.name,
            "project_id": str(registration.project_id) if registration.project_id else None,
            "token_id": str(token.id),
            "environment": env_name,
            "secrets": secrets_map,
            "allowlist": allowlist,
        }


class ActivityLogSelector:
    """
    Pure read-only query selector layer for Workspace Activity Logs (Tier 1 Managerial).
    """

    # Category -> queryset predicate. Categories are the dashboard's filter
    # taxonomy, not raw columns: rotation lives under secrets by target_type but
    # must be filterable on its own, and tokens span two target types.
    CATEGORY_FILTERS = {
        "secret": Q(action__startswith="secret.") & ~Q(action__startswith="secret.rotation"),
        "rotation": Q(action__startswith="secret.rotation"),
        "project": Q(target_type="project"),
        "environment": Q(target_type="environment"),
        "member": Q(target_type="member"),
        "allowlist": Q(target_type="allowlist"),
        "token": Q(target_type__in=["agent_token", "agent_token_family"]),
    }

    @staticmethod
    def apply_filters(qs, params: dict[str, Any]):
        simple = {
            "project_id": "project_id",
            "action": "action",
            "target_type": "target_type",
            "target_id": "target_id",
            "actor_email": "actor_email",
            "source": "source",
        }
        for param, field in simple.items():
            val = params.get(param)
            if val:
                qs = qs.filter(**{field: val})

        # Dashboard search: one box over the fields a reader recognises. Runs
        # server-side so it reaches beyond the loaded page, matching the
        # telemetry tab's behaviour.
        query = (params.get("q") or "").strip()
        if query:
            qs = qs.filter(
                Q(action__icontains=query)
                | Q(target_name__icontains=query)
                | Q(actor_email__icontains=query)
                | Q(target_type__icontains=query)
            )

        category = (params.get("category") or "").strip().lower()
        if category:
            predicate = ActivityLogSelector.CATEGORY_FILTERS.get(category)
            if predicate is not None:
                qs = qs.filter(predicate)

        since = params.get("since")
        if since:
            qs = qs.filter(created_at__gte=since)
        until = params.get("until")
        if until:
            qs = qs.filter(created_at__lte=until)
        return qs

    @staticmethod
    async def list_activity(
        *,
        workspace_id: str | uuid.UUID,
        params: dict[str, Any],
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        qs = WorkspaceActivityLog.objects.filter(workspace_id=workspace_id)
        qs = ActivityLogSelector.apply_filters(qs, params)
        # Plan retention applies to the managerial stream too: Free 3 days,
        # Pro 30. Clamping before paging keeps page boundaries honest.
        qs = await AuditSelector.apply_retention_floor(
            qs, workspace_id=workspace_id, field="created_at"
        )
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)

        fields = [
            "id",
            "workspace_id",
            "project_id",
            "actor_id",
            "actor_email",
            "action",
            "target_type",
            "target_id",
            "target_name",
            "metadata",
            "ip_address",
            "source",
            "created_at",
        ]
        logs = qs.order_by("-created_at").values(*fields)[offset : offset + limit]
        return [
            {
                "id": str(log["id"]),
                "workspace_id": str(log["workspace_id"]),
                "project_id": str(log["project_id"]) if log["project_id"] else None,
                "actor_id": str(log["actor_id"]) if log["actor_id"] else None,
                "actor_email": log["actor_email"],
                "action": log["action"],
                "target_type": log["target_type"],
                "target_id": log["target_id"],
                "target_name": log["target_name"],
                "metadata": log["metadata"] or {},
                "ip_address": log["ip_address"],
                "source": log["source"],
                "created_at": log["created_at"].isoformat() if log["created_at"] else "",
            }
            async for log in logs
        ]


class ForensicLogSelector:
    """
    Pure read-only query selector layer for Forensic Logs and Session Replay (Tier 3).
    """

    @staticmethod
    async def get_replay(*, log_id: str, user: User) -> dict[str, Any]:
        log = await ForensicAuditLogEntry.objects.filter(id=log_id).afirst()
        if not log:
            raise NotFoundError(f"Forensic log '{log_id}' not found")

        await WorkspaceSelector.get_membership(user=user, workspace_id=log.workspace_id)

        # Server-authoritative verification: recompute both hashes from the stored
        # fields and require exact matches. A record is verified only if its
        # content hash AND its chain linkage are intact; there is no fallback that
        # marks a record verified merely because a hash string is present.
        from .forensic_chain import compute_chain_hash, compute_entry_hash

        verified = False
        if log.created_at:
            expected_chain = compute_chain_hash(log.prev_chain_hash, str(log.id), log.created_at)
            expected_entry = compute_entry_hash(
                log.event_json or {},
                log.snapshot_json or {},
                log.enforcement_json or {},
                log.resolution_json or {},
            )
            verified = bool(log.chain_hash) and log.chain_hash == expected_chain
            verified = verified and bool(log.entry_hash) and log.entry_hash == expected_entry

        event_data = log.event_json or {}
        snapshot_data = log.snapshot_json or {}
        enforcement_data = log.enforcement_json or {}
        resolution_data = log.resolution_json or {}

        return {
            "id": str(log.id),
            "workspace_id": str(log.workspace_id),
            "project_id": str(log.project_id) if log.project_id else None,
            "stream_id": log.stream_id,
            "stream_seq": log.stream_seq,
            "prev_chain_hash": log.prev_chain_hash,
            "chain_hash": log.chain_hash,
            "entry_hash": log.entry_hash,
            "created_at": log.created_at.isoformat() if log.created_at else "",
            "event": event_data,
            "snapshot": snapshot_data,
            "enforcement": enforcement_data,
            "resolution": resolution_data,
            "steps": {
                "1_event": event_data,
                "2_snapshot": snapshot_data,
                "3_enforcement": enforcement_data,
                "4_resolution": resolution_data,
            },
            "verified": verified,
        }



class CloudSyncSelector:
    """Builds the control-plane → resolver workspace sync payload (spec 14).

    Returns the active delegation (so the resolver knows which CEDK private key
    unseals the DEK), the allowlist, and every secret as its Fernet-unwrapped
    DEK-ciphertext. The server strips only its OWN envelope; the value stays
    AES-GCM-encrypted under the workspace DEK, so the resolver (which holds the
    DEK via CEDK) performs the final decrypt. Plaintext never leaves the client.
    """

    @staticmethod
    async def build_sync_payload(*, workspace_id: uuid.UUID) -> dict[str, Any]:
        from .models import CloudDelegationKey, Workspace, WorkspaceAllowlist
        from apps.common.services.encryption import EncryptionService
        from apps.secrets_app.models import Secret

        # 1. Active delegation (single active resolver registration per workspace).
        delegation = await CloudDelegationKey.objects.filter(
            workspace_id=workspace_id, is_active=True
        ).afirst()
        sealed_workspace_key = delegation.sealed_workspace_key if delegation else None
        delegation_public_key = delegation.public_key if delegation else None

        # 2. Allowlist domains.
        allowlist = [d async for d in WorkspaceAllowlist.objects.filter(
            workspace_id=workspace_id
        ).values_list("domain", flat=True)]

        # 3. Secrets across all projects in the workspace. Fernet-unwrap so the
        #    value is the client's DEK-AES-GCM ciphertext ([12B nonce][ct+16B tag]).
        secrets: list[dict[str, Any]] = []
        latest = None
        async for s in Secret.objects.filter(project__workspace_id=workspace_id).select_related("project"):
            try:
                dek_ciphertext = EncryptionService.decrypt(s.value)
            except Exception as exc:
                logger.warning("SYNC_SKIP: could not unwrap secret %s/%s: %s", s.project_id, s.key, exc)
                continue
            secrets.append({
                "project_id": str(s.project_id),
                "project_name": s.project.name,
                "environment": s.environment,
                "key": s.key,
                "value": dek_ciphertext,
                "policy": s.policy or {},
                "updated_at": s.updated_at.isoformat() if s.updated_at else None,
            })
            if s.updated_at and (latest is None or s.updated_at > latest):
                latest = s.updated_at

        # 4. Version watermark: max updated_at across delegation/allowlist/secrets.
        if delegation and delegation.updated_at and (latest is None or delegation.updated_at > latest):
            latest = delegation.updated_at

        # 5. Billing entitlement for quota attribution by quota-enforcing
        # consumers (e.g. the cloud resolver's login posture, which has no
        # token-bound billing id). None when the workspace has no billing.
        workspace = await Workspace.objects.filter(id=workspace_id).afirst()
        billing_id = getattr(workspace, "effective_billing_id", None) if workspace else None

        return {
            "workspace_id": str(workspace_id),
            "version": latest.isoformat() if latest else None,
            "sealed_workspace_key": sealed_workspace_key,
            "public_key": delegation_public_key,
            "has_delegation": bool(delegation),
            "allowlist": allowlist,
            "billing_id": billing_id,
            "secrets": secrets,
        }
