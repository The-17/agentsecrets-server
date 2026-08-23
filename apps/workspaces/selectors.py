from __future__ import annotations

import logging
import uuid
from typing import Any
from django.db.models import Count, Max, Q, Subquery, OuterRef, IntegerField
from django.db.models.functions import Coalesce
from asgiref.sync import sync_to_async

from apps.accounts.models import User
from apps.common.exceptions import (
    NotFoundError,
    AuthorizationError,
    BodyValidationError,
)
from .models import (
    Workspace,
    Membership,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
    WorkspaceAllowlistLog,
    AgentRegistration,
    AgentToken,
    AuditLogEntry,
    IdentityLevel,
)

logger = logging.getLogger("apps.workspaces")


class WorkspaceSelector:
    """
    Pure read-only query selector layer for Workspaces and Memberships.
    """

    @staticmethod
    async def get_membership(*, user: User, workspace_id: uuid.UUID) -> Membership:
        member = await Membership.objects.filter(
            user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE
        ).select_related("workspace").afirst()
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
            "workspace__created_at",
        )
        return [
            {
                "id": str(m["workspace__id"]),
                "name": m["workspace__name"],
                "type": m["workspace__type"],
                "role": m["role"],
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

        data: list[dict[str, Any]] = []
        async for t in AgentToken.objects.filter(registration_id=registration_id):
            data.append({
                "id": str(t.id),
                "label": t.label,
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
                "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
                "created_at": t.created_at.isoformat(),
            })
        return data


class AuditSelector:
    """
    Pure read-only query selector layer for Audit Logs.
    """

    @staticmethod
    def apply_filters(qs, params: dict[str, Any]):
        simple = {
            "project_id": "project_id",
            "agent_id": "agent_id",
            "agent_token_id": "agent_token_id",
            "identity_level": "identity_level",
            "credential_ref": "credential_ref",
            "environment": "environment",
            "resolution_path": "resolution_path",
        }
        for param, field in simple.items():
            val = params.get(param)
            if val:
                qs = qs.filter(**{field: val})
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
    async def list_audit_logs(*, workspace_id: str, params: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
        qs = AuditSelector.apply_filters(
            AuditLogEntry.objects.filter(workspace_id=workspace_id).exclude(identity_level=IdentityLevel.USER),
            params,
        )
        limit = max(1, min(limit, 1000))
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
        ]
        logs = qs.order_by("-timestamp").values(*fields)[:limit]
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
                "error": log["error"],
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
    async def get_audit_log_summary(
        *,
        workspace_id: str,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        qs = AuditLogEntry.objects.filter(workspace_id=workspace_id).exclude(identity_level=IdentityLevel.USER)
        if start:
            qs = qs.filter(timestamp__gte=start)
        if end:
            qs = qs.filter(timestamp__lte=end)

        total_requests = await qs.acount()
        total_errors = await qs.filter(status_code__gte=400).acount()

        by_agent = await sync_to_async(list)(
            qs.exclude(agent_id__isnull=True).exclude(agent_id="").values("agent_id").annotate(
                count=Count("id"),
                failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
            ).order_by("-count")
        )
        by_domain = await sync_to_async(list)(
            qs.values("target_domain").annotate(
                count=Count("id"),
                failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
            ).order_by("-count")
        )
        by_credential = await sync_to_async(list)(
            qs.values("credential_ref").annotate(
                count=Count("id"),
                failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
            ).order_by("-count")
        )
        anon_count = await qs.filter(identity_level=IdentityLevel.ANONYMOUS).acount()

        return {
            "period": {"start": start or "all", "end": end or "all"},
            "totals": {"requests": total_requests, "errors": total_errors},
            "by_agent": [{"agent_id": r["agent_id"], "count": r["count"], "failed": r["failed"]} for r in by_agent],
            "by_credential": [{"credential_ref": r["credential_ref"], "count": r["count"], "failed": r["failed"]} for r in by_credential],
            "by_domain": [{"domain": r["target_domain"], "count": r["count"], "failed": r["failed"]} for r in by_domain],
            "anonymous_call_count": anon_count,
        }


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


class WorkloadSelector:
    """Selector for headless container workload secret deliveries."""

    @staticmethod
    async def resolve_env_payload(*, raw_token: str, env_override: str | None = None) -> dict[str, Any]:
        import hashlib
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        token = await AgentToken.objects.select_related("registration", "registration__workspace").filter(
            token_hash=token_hash
        ).afirst()

        if not token:
            raise AuthorizationError("Invalid or revoked workload token")

        if token.expires_at and token.expires_at < timezone.now():
            raise AuthorizationError("Workload token has expired")

        registration = token.registration
        workspace = registration.workspace
        env_name = env_override or registration.environment or "production"

        # Query secrets for this project & environment
        from apps.secrets_app.models import Secret
        secrets_qs = Secret.objects.filter(
            project_id=registration.project_id,
            environment=env_name,
            revoked_at__isnull=True
        ).values("key", "value")

        secrets_map = {}
        async for s in secrets_qs:
            secrets_map[s["key"]] = s["value"]

        # Query active domain allowlist for this workspace
        allowlist_qs = WorkspaceAllowlist.objects.filter(
            workspace_id=workspace.id,
            is_active=True
        ).values_list("domain", flat=True)

        allowlist = [d async for d in allowlist_qs]

        return {
            "workspace_id": str(workspace.id),
            "workspace_name": workspace.name,
            "agent_name": registration.name,
            "environment": env_name,
            "secrets": secrets_map,
            "allowlist": allowlist,
        }
