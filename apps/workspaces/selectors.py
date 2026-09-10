from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any
from django.conf import settings
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

        data: list[dict[str, Any]] = []
        async for t in AgentToken.objects.filter(registration_id=registration_id):
            data.append({
                "id": str(t.id),
                "label": t.label,
                "environment": getattr(t, "environment", None) or "",
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
            "source": "source",
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
            "source",
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
        from apps.secrets_app.models import Secret
        from apps.common.services.encryption import EncryptionService

        filter_kwargs = {"environment": env_name}
        if registration.project_id:
            filter_kwargs["project_id"] = registration.project_id
        else:
            filter_kwargs["project__workspace_id"] = workspace.id

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
            "environment": env_name,
            "secrets": secrets_map,
            "allowlist": allowlist,
        }


class ActivityLogSelector:
    """
    Pure read-only query selector layer for Workspace Activity Logs (Tier 1 Managerial).
    """

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
        from .models import CloudDelegationKey, WorkspaceAllowlist
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

        return {
            "workspace_id": str(workspace_id),
            "version": latest.isoformat() if latest else None,
            "sealed_workspace_key": sealed_workspace_key,
            "public_key": delegation_public_key,
            "has_delegation": bool(delegation),
            "allowlist": allowlist,
            "secrets": secrets,
        }
