from __future__ import annotations

import hashlib
import hmac as hmac_module
import json
import logging
import secrets as secrets_module
import uuid
from typing import Any
from django.db import transaction
from django.utils import timezone
from asgiref.sync import sync_to_async

from apps.accounts.models import User
from apps.common.exceptions import (
    NotFoundError,
    AuthorizationError,
    BodyValidationError,
)
from apps.secrets_app.models import Project
from .models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
    WorkspaceAllowlistLog,
    AgentRegistration,
    AgentToken,
    AuditLogEntry,
    IdentityLevel,
)
from .schemas import (
    WorkspaceCreateSchema,
    WorkspaceUpdateSchema,
    InviteEntrySchema,
    AgentCreateSchema,
    AgentTokenCreateSchema,
    InternalAgentVerifySchema,
)
from .selectors import WorkspaceSelector, AgentSelector

logger = logging.getLogger("apps.workspaces")


class WorkspaceService:
    """
    Domain service layer for Workspace creation, updates, deletions, and memberships.
    """

    @staticmethod
    async def create_workspace(*, user: User, data: WorkspaceCreateSchema) -> dict[str, Any]:
        @sync_to_async
        def _create():
            with transaction.atomic():
                ws = Workspace.objects.create(
                    name=data.name, owner=user, type=WorkspaceType.SHARED
                )
                Membership.objects.create(
                    user=user,
                    workspace=ws,
                    role=MembershipRole.OWNER,
                    status=MembershipStatus.ACTIVE,
                    encrypted_workspace_key=data.encrypted_workspace_key,
                )
                return ws

        workspace = await _create()
        logger.info(f"WORKSPACE_CREATED: Workspace '{workspace.name}' (ID: {workspace.id}) created")
        return {
            "id": str(workspace.id),
            "name": workspace.name,
            "type": workspace.type,
            "role": MembershipRole.OWNER,
        }

    @staticmethod
    async def update_workspace(*, user: User, workspace_id: uuid.UUID, data: WorkspaceUpdateSchema) -> dict[str, Any]:
        m = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("You don't have permission to update this workspace")
        ws = m.workspace
        if data.name:
            ws.name = data.name
        await ws.asave(update_fields=["name", "updated_at"])
        return {"id": str(ws.id), "name": ws.name, "type": ws.type}

    @staticmethod
    async def delete_workspace(*, user: User, workspace_id: uuid.UUID) -> str:
        m = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if m.role != MembershipRole.OWNER:
            raise AuthorizationError("Only the workspace owner can delete it")
        ws = m.workspace
        if ws.type == WorkspaceType.PERSONAL:
            raise AuthorizationError("Personal workspaces cannot be deleted")
        name = ws.name
        await ws.adelete()
        logger.warning(f"WORKSPACE_DELETED: Workspace '{name}' (ID: {workspace_id}) deleted")
        return name


class MemberService:
    """
    Domain service layer for Workspace Member operations and invitations.
    """

    @staticmethod
    async def process_member_invites(
        *,
        user: User,
        workspace_id: uuid.UUID,
        entries: list[InviteEntrySchema],
    ) -> tuple[list[dict[str, Any]], bool]:
        um = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if um.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only workspace admins can invite members.")

        results = []
        any_created = False

        for invite in entries:
            try:
                invitee = await User.objects.filter(email=invite.email).afirst()
                if not invitee:
                    results.append({"email": invite.email, "error": "User not found"})
                    continue

                if await Membership.objects.filter(user=invitee, workspace_id=workspace_id).aexists():
                    results.append({"email": invite.email, "error": "Already a member"})
                    continue

                await Membership.objects.acreate(
                    user=invitee,
                    workspace_id=workspace_id,
                    role=invite.role,
                    status=MembershipStatus.ACTIVE,
                    encrypted_workspace_key=invite.encrypted_workspace_key,
                )
                logger.info(
                    f"MEMBER_INVITED: User invited to workspace {workspace_id} with role {invite.role}"
                )
                results.append({"email": invite.email, "error": ""})
                any_created = True

            except Exception as e:
                logger.error(
                    f"MEMBER_INVITE_FAILED: Error inviting to workspace {workspace_id}: {type(e).__name__}"
                )
                results.append({"email": invite.email, "error": str(e)})

        return results, any_created

    @staticmethod
    async def update_member_role(
        *,
        user: User,
        workspace_id: uuid.UUID,
        target_user_id: uuid.UUID,
        role: str,
    ) -> dict[str, Any]:
        um = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if um.role not in [MembershipRole.ADMIN, MembershipRole.OWNER]:
            raise AuthorizationError("Only admins/owners can update member roles.")
        tm = await Membership.objects.filter(
            user_id=target_user_id, workspace_id=workspace_id
        ).select_related("user").afirst()
        if not tm:
            raise NotFoundError("User is not a member of this workspace.")
        if tm.role == MembershipRole.OWNER:
            raise AuthorizationError("Cannot change role of the workspace owner.")
        if role == MembershipRole.OWNER:
            raise AuthorizationError("Cannot promote member to OWNER. Transfer ownership instead.")

        tm.role = role
        await tm.asave(update_fields=["role", "updated_at"])
        return {"user_id": str(target_user_id), "email": tm.user.email, "role": tm.role}

    @staticmethod
    async def remove_member(
        *,
        user: User,
        workspace_id: uuid.UUID,
        target_user_id: uuid.UUID,
    ) -> str:
        um = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        tm = await Membership.objects.filter(
            user_id=target_user_id, workspace_id=workspace_id
        ).select_related("user").afirst()
        if not tm:
            raise NotFoundError("Member not found in this workspace")
        if tm.role == MembershipRole.OWNER:
            raise AuthorizationError("Cannot remove the workspace owner")
        if um.role == MembershipRole.ADMIN and tm.role == MembershipRole.ADMIN:
            raise AuthorizationError("Admins cannot remove other admins")
        if um.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("You don't have permission to remove members")
        email = tm.user.email
        await tm.adelete()
        logger.warning(f"MEMBER_REMOVED: Member removed from workspace {workspace_id}")
        return email

    @staticmethod
    async def change_member_role_action(
        *,
        user: User,
        workspace_id: uuid.UUID,
        target_user_id: uuid.UUID,
        action: str,
    ) -> dict[str, Any]:
        um = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if um.role not in [MembershipRole.ADMIN, MembershipRole.OWNER]:
            raise AuthorizationError("Only admins/owners can change member roles.")
        tm = await Membership.objects.filter(
            user_id=target_user_id, workspace_id=workspace_id
        ).select_related("user").afirst()
        if not tm:
            raise NotFoundError("User is not a member of this workspace.")

        if action == "demote":
            if tm.role in [MembershipRole.ADMIN, MembershipRole.OWNER]:
                count = await Membership.objects.filter(
                    workspace_id=workspace_id,
                    role__in=[MembershipRole.ADMIN, MembershipRole.OWNER],
                    status=MembershipStatus.ACTIVE,
                ).acount()
                if count <= 1:
                    raise BodyValidationError("action", "You are the only admin. Promote another member first.")
            tm.role = MembershipRole.MEMBER
        elif action == "promote":
            tm.role = MembershipRole.ADMIN

        await tm.asave(update_fields=["role", "updated_at"])
        return {"user_id": str(tm.user.id), "role": tm.role}


class AllowlistService:
    """
    Domain service layer for Allowlist domain additions and deletions.
    """

    @staticmethod
    async def bulk_add_domains(
        *,
        user: User,
        workspace_id: uuid.UUID,
        domains: list[str],
    ) -> list[dict[str, Any]]:
        m = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only admins/owners can manage the allowlist")

        existing = set()
        async for d in WorkspaceAllowlist.objects.filter(workspace_id=workspace_id, domain__in=domains).values_list("domain", flat=True):
            existing.add(d)

        new_domains = [d for d in domains if d not in existing]
        if not new_domains:
            raise BodyValidationError("domains", "All provided domains are already in the allowlist.")

        @sync_to_async
        def _insert_records():
            with transaction.atomic():
                entries = WorkspaceAllowlist.objects.bulk_create(
                    [WorkspaceAllowlist(workspace_id=workspace_id, domain=d, added_by=user) for d in new_domains]
                )
                WorkspaceAllowlistLog.objects.bulk_create(
                    [WorkspaceAllowlistLog(workspace_id=workspace_id, domain=d, action="added", performed_by=user) for d in new_domains]
                )
                return entries

        entries = await _insert_records()
        for e in entries:
            e.added_by = user
        return [
            {
                "id": str(e.id),
                "domain": e.domain,
                "added_by_email": e.added_by.email,
                "added_at": e.added_at.isoformat() if e.added_at else None,
            }
            for e in entries
        ]

    @staticmethod
    async def remove_domain(
        *,
        user: User,
        workspace_id: uuid.UUID,
        domain: str,
    ) -> None:
        m = await WorkspaceSelector.get_membership(user=user, workspace_id=workspace_id)
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only admins/owners can manage the allowlist")

        entry = await WorkspaceAllowlist.objects.filter(workspace_id=workspace_id, domain=domain.lower()).afirst()
        if not entry:
            raise NotFoundError(f"{domain} is not in the allowlist.")

        @sync_to_async
        def _delete_and_log():
            with transaction.atomic():
                WorkspaceAllowlist.objects.filter(id=entry.id).delete()
                WorkspaceAllowlistLog.objects.create(
                    workspace_id=workspace_id,
                    domain=domain.lower(),
                    action="removed",
                    performed_by=user,
                )

        await _delete_and_log()


class AgentService:
    """
    Domain service layer for Agent Registration, Tokens, and verification.
    """

    @staticmethod
    async def create_agent_with_token(
        *,
        user: User,
        workspace_id: uuid.UUID,
        payload: AgentCreateSchema,
        project_id: uuid.UUID | None = None,
    ) -> tuple[dict[str, Any], str, str]:
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        raw_token = secrets_module.token_urlsafe(32)
        expires_at = timezone.now() + timezone.timedelta(days=payload.expires_in_days) if payload.expires_in_days else None

        @sync_to_async
        def _create_agent_and_token():
            with transaction.atomic():
                kwargs = {"workspace_id": workspace_id, "name": payload.name, "created_by": user}
                if project_id:
                    kwargs["project_id"] = project_id
                agent = AgentRegistration.objects.create(**kwargs)
                token = AgentToken.objects.create(
                    registration=agent,
                    workspace_id=workspace_id,
                    token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
                    label=payload.label,
                    expires_at=expires_at,
                    created_by=user,
                )
                return agent, token

        agent, token = await _create_agent_and_token()
        agent_data = AgentSelector.serialize_agent(agent)
        agent_data["token_count"] = 1
        agent_data["active_token_count"] = 1
        return agent_data, raw_token, str(token.id)

    @staticmethod
    async def delete_agent(*, user: User, workspace_id: uuid.UUID, registration_id: str) -> None:
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        agent = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        await agent.adelete()

    @staticmethod
    async def update_agent_capabilities(
        *,
        user: User,
        workspace_id: uuid.UUID,
        registration_id: str,
        capabilities: dict[str, Any],
    ) -> dict[str, Any]:
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        agent = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        agent.capabilities = capabilities
        await agent.asave(update_fields=["capabilities", "updated_at"])
        return agent.capabilities or {}

    @staticmethod
    async def create_agent_token(
        *,
        user: User,
        workspace_id: uuid.UUID,
        registration_id: str,
        data: AgentTokenCreateSchema,
    ) -> tuple[str, str, dict[str, Any]]:
        exists = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).aexists()
        if not exists:
            raise NotFoundError("Agent not found")
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)

        expires_at = timezone.now() + timezone.timedelta(days=data.expires_in_days) if data.expires_in_days else None
        raw_token = secrets_module.token_urlsafe(32)
        token = await AgentToken.objects.acreate(
            registration_id=registration_id,
            workspace_id=workspace_id,
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            label=data.label,
            expires_at=expires_at,
            created_by=user,
        )
        return (
            raw_token,
            str(token.id),
            {
                "id": str(token.id),
                "label": token.label,
                "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                "created_at": token.created_at.isoformat(),
            },
        )

    @staticmethod
    async def delete_agent_token(
        *,
        user: User,
        workspace_id: uuid.UUID,
        registration_id: str,
        token_id: str,
    ) -> None:
        exists = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).aexists()
        if not exists:
            raise NotFoundError("Agent not found")
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        token = await AgentToken.objects.filter(id=token_id, registration_id=registration_id).afirst()
        if not token:
            raise NotFoundError("Token not found")
        await token.adelete()

    @staticmethod
    async def bulk_delete_agent_tokens(
        *,
        user: User,
        workspace_id: uuid.UUID,
        registration_id: str,
    ) -> None:
        exists = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).aexists()
        if not exists:
            raise NotFoundError("Agent not found")
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        await AgentToken.objects.filter(registration_id=registration_id).adelete()

    @staticmethod
    async def verify_agent_token(*, auth_caller: Any, data: InternalAgentVerifySchema) -> dict[str, Any]:
        token_hash = hashlib.sha256(data.token.encode()).hexdigest()

        if data.token_id:
            token = await AgentToken.objects.select_related("registration").filter(id=data.token_id).afirst()
        else:
            token = await AgentToken.objects.select_related("registration").filter(token_hash=token_hash).afirst()

        if not token:
            return {"valid": False, "reason": "Not found"}

        if isinstance(auth_caller, User):
            has_access = await Membership.objects.filter(
                user=auth_caller, workspace_id=token.workspace_id, status=MembershipStatus.ACTIVE
            ).aexists()
            if not has_access:
                return {"valid": False, "reason": "Unauthorized workspace access"}

        if not hmac_module.compare_digest(token_hash, token.token_hash):
            return {"valid": False, "reason": "Invalid token"}

        if token.revoked_at:
            return {"valid": False, "reason": "Revoked"}

        if token.expires_at and token.expires_at < timezone.now():
            return {"valid": False, "reason": "Expired"}

        token.last_used_at = timezone.now()
        await token.asave(update_fields=["last_used_at"])

        agent = token.registration
        return {
            "valid": True,
            "agent_id": str(agent.id),
            "agent_name": agent.name,
            "workspace_id": str(token.workspace_id),
            "project_id": str(agent.project_id) if agent.project_id else None,
            "environment": token.environment,
            "capabilities": agent.capabilities or {},
            "token_id": str(token.id),
        }

    @staticmethod
    async def ingest_audit_logs(*, entries: list[dict[str, Any]]) -> tuple[int, list[str]]:
        ws_ids = {e.get("workspace_id") for e in entries if e.get("workspace_id")}
        prj_ids = {e.get("project_id") for e in entries if e.get("project_id")}
        token_ids = {e.get("token_id") for e in entries if e.get("token_id")}

        existing_ws = set()
        if ws_ids:
            async for w_id in Workspace.objects.filter(id__in=ws_ids).values_list("id", flat=True):
                existing_ws.add(str(w_id))

        existing_prj = set()
        if prj_ids:
            async for p_id in Project.objects.filter(id__in=prj_ids).values_list("id", flat=True):
                existing_prj.add(str(p_id))

        existing_tokens = set()
        if token_ids:
            async for t_id in AgentToken.objects.filter(id__in=token_ids).values_list("id", flat=True):
                existing_tokens.add(str(t_id))

        char_limits = {
            "id": 64,
            "environment": 20,
            "agent_id": 64,
            "identity_level": 20,
            "credential_ref": 255,
            "injection_style": 50,
            "target_domain": 253,
            "method": 10,
            "redaction_reason": 255,
            "resolution_path": 50,
            "caller_role": 50,
            "session_id": 255,
            "policy_snapshot_id": 255,
        }

        direct_fields = [
            "id", "schema_version", "timestamp", "environment",
            "agent_id", "identity_level", "method", "target_url",
            "target_path", "status_code", "duration_ms", "proxy_duration_ms",
            "redacted", "redaction_reason", "resolution_path",
            "allowlist_snapshot", "caller_role", "session_id",
            "policy_snapshot_id", "error", "credential_ref", "injection_style",
            "target_domain",
        ]

        model_entries: list[AuditLogEntry] = []
        for e in entries:
            mapped: dict[str, Any] = {}
            for field in direct_fields:
                if field in e:
                    mapped[field] = e[field]

            if "domain" in e and "target_domain" not in mapped:
                mapped["target_domain"] = e["domain"]

            ws_val = str(e.get("workspace_id")) if e.get("workspace_id") else None
            if ws_val and ws_val in existing_ws:
                mapped["workspace_id"] = ws_val
            else:
                continue

            prj_val = str(e.get("project_id")) if e.get("project_id") else None
            mapped["project_id"] = prj_val if prj_val in existing_prj else None

            tok_val = str(e.get("token_id")) if e.get("token_id") else None
            mapped["agent_token_id"] = tok_val if tok_val in existing_tokens else None

            mapped["credential_ref"] = mapped.get("credential_ref") or ""
            mapped["injection_style"] = mapped.get("injection_style") or ""
            mapped["target_domain"] = mapped.get("target_domain") or ""
            mapped["target_url"] = mapped.get("target_url") or ""
            mapped["target_path"] = mapped.get("target_path") or ""
            mapped["method"] = (mapped.get("method") or "GET").upper()
            mapped["duration_ms"] = mapped.get("duration_ms") if mapped.get("duration_ms") is not None else 0
            mapped["resolution_path"] = mapped.get("resolution_path") or "unknown"
            mapped["caller_role"] = mapped.get("caller_role") or "unknown"

            for field, limit in char_limits.items():
                if field in mapped and isinstance(mapped[field], str) and len(mapped[field]) > limit:
                    mapped[field] = mapped[field][:limit]

            model_entries.append(AuditLogEntry(**mapped))

        if not model_entries:
            return 0, []

        created = await AuditLogEntry.objects.abulk_create(model_entries, ignore_conflicts=True)
        return len(created), [str(log.id) for log in created]


class CloudDelegationService:
    """Service for managing Cloud Resolver delegation keys."""

    @staticmethod
    async def save_delegation(
        *,
        user: User,
        workspace_id: uuid.UUID,
        resolver_name: str,
        public_key: str,
        sealed_workspace_key: str,
    ) -> dict[str, Any]:
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        from .models import CloudDelegationKey

        delegation, _ = await CloudDelegationKey.objects.aupdate_or_create(
            workspace_id=workspace_id,
            resolver_name=resolver_name,
            defaults={
                "public_key": public_key,
                "sealed_workspace_key": sealed_workspace_key,
                "is_active": True,
                "revoked_at": None,
            }
        )

        return {
            "id": str(delegation.id),
            "workspace_id": str(workspace_id),
            "resolver_name": delegation.resolver_name,
            "public_key": delegation.public_key,
            "is_active": delegation.is_active,
        }

    @staticmethod
    async def revoke_delegation(*, user: User, workspace_id: uuid.UUID) -> None:
        await WorkspaceSelector.check_admin(user=user, workspace_id=workspace_id)
        from .models import CloudDelegationKey
        from django.utils import timezone

        await CloudDelegationKey.objects.filter(workspace_id=workspace_id).aupdate(
            is_active=False,
            revoked_at=timezone.now(),
        )


class WorkloadService:
    """Service for headless container runtime delivery."""

    @staticmethod
    async def deliver_env_secrets(*, raw_token: str, env_override: str | None = None) -> dict[str, Any]:
        data = await WorkloadSelector.resolve_env_payload(raw_token=raw_token, env_override=env_override)
        
        # Async track +1 Workload Startup Event in Billing
        try:
            from apps.billing.services import BillingService
            import uuid
            ws_id = uuid.UUID(data["workspace_id"])
            await BillingService.record_usage_event(workspace_id=ws_id, count=1)
        except Exception:
            pass

        return data
