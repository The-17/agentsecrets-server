# Standard library
import hashlib
import hmac as hmac_module
import json
import logging
import secrets as secrets_module
import uuid


logger = logging.getLogger("apps.workspaces")

# Django
from django.db.models import Count, Max, Q
from django.http import StreamingHttpResponse
from django.utils import timezone
from django.conf import settings
from asgiref.sync import sync_to_async

# Third-party
from ninja_extra import api_controller, route

# Local
from apps.common.auth import JWTAuth, ResolverServiceKeyAuth, InternalOrUserAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse
from apps.common.exceptions import (
    NotFoundError, AuthorizationError, BodyValidationError, ConflictError,
)
from apps.accounts.models import User
from .mixins import WorkspaceMixin
from .models import (
    Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus,
    WorkspaceAllowlist, WorkspaceAllowlistLog,
    AgentRegistration, AgentToken, AuditLogEntry, IdentityLevel,
)
from .schemas import (
    WorkspaceCreateSchema, WorkspaceUpdateSchema,
    MemberInviteSchema, MemberUpdateSchema, MemberRoleActionSchema,
    InviteEntrySchema, BatchInviteSchema,
    AllowlistBulkCreateSchema,
    AgentCreateSchema, AgentTokenCreateSchema,
    AgentCapabilitiesSchema,
    InternalAgentVerifySchema,
)

logger = logging.getLogger("apps.workspaces")


@api_controller("/workspaces", tags=["Workspaces"], auth=JWTAuth())
class WorkspaceController(WorkspaceMixin):

    async def _get_membership(self, user, workspace_id):
        member = await Membership.objects.filter(user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE).select_related("workspace").afirst()
        if not member:
            raise NotFoundError("Workspace not found or you don't have access")
        return member

    @route.get("/", response={200: dict})
    async def list_workspaces(self, request):
        memberships = Membership.objects.filter(
            user=request.auth, status=MembershipStatus.ACTIVE
        ).values(
            "role", "encrypted_workspace_key",
            "workspace__id", "workspace__name", "workspace__type", "workspace__created_at"
        )
        data = [
            {
                "id": str(m["workspace__id"]), "name": m["workspace__name"], "type": m["workspace__type"],
                "role": m["role"], "encrypted_workspace_key": m["encrypted_workspace_key"],
                "created_at": m["workspace__created_at"].isoformat() if m["workspace__created_at"] else None,
            }
            async for m in memberships
        ]
        return CustomResponse.success(message="Workspaces retrieved successfully", data=data)

    @route.post("/", response={201: dict})
    async def create_workspace(self, request, data: WorkspaceCreateSchema):
        workspace = await Workspace.objects.acreate(name=data.name, owner=request.auth, type=WorkspaceType.SHARED)
        await Membership.objects.acreate(user=request.auth, workspace=workspace, role=MembershipRole.OWNER, status=MembershipStatus.ACTIVE, encrypted_workspace_key=data.encrypted_workspace_key)
        logger.info(f"WORKSPACE_CREATED: Workspace '{workspace.name}' (ID: {workspace.id}) created by user {request.auth.email}")
        return CustomResponse.success(message="Workspace created successfully", data={
            "id": str(workspace.id), "name": workspace.name, "type": workspace.type, "role": MembershipRole.OWNER,
        }, status_code=201)

    @route.get("/{workspace_id}/", response={200: dict, 404: ErrorResponse})
    async def get_workspace(self, request, workspace_id: uuid.UUID):
        m = await self._get_membership(request.auth, workspace_id)
        ws = m.workspace
        return CustomResponse.success(message="Workspace retrieved successfully", data={
            "id": str(ws.id), "name": ws.name, "type": ws.type, "role": m.role,
            "encrypted_workspace_key": m.encrypted_workspace_key,
            "created_at": ws.created_at.isoformat(), "updated_at": ws.updated_at.isoformat(),
        })

    @route.patch("/{workspace_id}/", response={200: dict, 403: ErrorResponse})
    async def update_workspace(self, request, workspace_id: uuid.UUID, data: WorkspaceUpdateSchema):
        m = await self._get_membership(request.auth, workspace_id)
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("You don't have permission to update this workspace")
        ws = m.workspace
        if data.name:
            ws.name = data.name
        await ws.asave()
        return CustomResponse.success(message="Workspace updated successfully", data={"id": str(ws.id), "name": ws.name, "type": ws.type})

    @route.delete("/{workspace_id}/", response={200: SuccessResponse, 403: ErrorResponse})
    async def delete_workspace(self, request, workspace_id: uuid.UUID):
        m = await self._get_membership(request.auth, workspace_id)
        ws = m.workspace
        if m.role != MembershipRole.OWNER:
            raise AuthorizationError("Only the workspace owner can delete it")
        if ws.type == WorkspaceType.PERSONAL:
            raise AuthorizationError("Personal workspaces cannot be deleted")
        name = ws.name
        await ws.adelete()
        logger.warning(f"WORKSPACE_DELETED: Workspace '{name}' (ID: {workspace_id}) deleted by user {request.auth.email}")
        return CustomResponse.success(message=f"Workspace '{name}' deleted successfully")

    # --- Members ---

    @route.get("/{workspace_id}/members/", response={200: dict, 404: ErrorResponse})
    async def list_members(self, request, workspace_id: uuid.UUID):
        await self._get_membership(request.auth, workspace_id)
        memberships = Membership.objects.filter(workspace_id=workspace_id).values(
            "id", "user_id", "user__email", "user__first_name", "user__last_name", "role", "status", "created_at"
        )
        data = [
            {
                "id": str(m["id"]), "user_id": str(m["user_id"]), "email": m["user__email"],
                "name": f"{m['user__first_name']} {m['user__last_name']}",
                "role": m["role"], "status": m["status"], "created_at": m["created_at"].isoformat() if m["created_at"] else None,
            }
            async for m in memberships
        ]
        return CustomResponse.success(message="Members retrieved successfully", data=data)

    @route.post("/{workspace_id}/members/", response={201: dict, 200: dict, 403: ErrorResponse, 404: ErrorResponse})
    async def invite_member(self, request, workspace_id: uuid.UUID, data: dict = None):
        um = await self._get_membership(request.auth, workspace_id)
        if um.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only workspace admins can invite members.")

        # Parse the raw body to detect batch vs single format
        body = json.loads(request.body)

        if "invites" in body:
            # Batch format: {"invites": [{...}, {...}]}
            parsed = BatchInviteSchema(**body)
            entries = parsed.invites
        else:
            # Single format (backward compat): {"email": ..., "role": ..., ...}
            entry = InviteEntrySchema(**body)
            entries = [entry]

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
                    f"MEMBER_INVITED: User {invite.email} invited to workspace "
                    f"{workspace_id} with role {invite.role} by user {request.auth.email}"
                )
                results.append({"email": invite.email, "error": ""})
                any_created = True

            except Exception as e:
                logger.error(f"MEMBER_INVITE_FAILED: Error inviting {invite.email} to workspace {workspace_id}: {e}")
                results.append({"email": invite.email, "error": str(e)})

        status_code = 201 if any_created else 200
        return CustomResponse.success(
            message="Invites processed",
            data=results,
            status_code=status_code,
        )

    @route.patch("/{workspace_id}/members/{user_id}/", response={200: dict, 403: ErrorResponse, 404: ErrorResponse})
    async def update_member(self, request, workspace_id: uuid.UUID, user_id: uuid.UUID, data: MemberUpdateSchema):
        um = await self._get_membership(request.auth, workspace_id)
        tm = await Membership.objects.filter(user_id=user_id, workspace_id=workspace_id).select_related("user").afirst()
        if not tm:
            raise NotFoundError("Member not found in this workspace")
        if um.role != MembershipRole.OWNER:
            raise AuthorizationError("Only the workspace owner can change member roles")
        if tm.role == MembershipRole.OWNER:
            raise AuthorizationError("Cannot change the owner's role")
        tm.role = data.role
        await tm.asave()
        return CustomResponse.success(message=f"Member role updated to {data.role}", data={"user_id": str(tm.user.id), "email": tm.user.email, "role": tm.role})

    @route.delete("/{workspace_id}/members/{user_id}/", response={200: SuccessResponse, 403: ErrorResponse})
    async def remove_member(self, request, workspace_id: uuid.UUID, user_id: uuid.UUID):
        um = await self._get_membership(request.auth, workspace_id)
        tm = await Membership.objects.filter(user_id=user_id, workspace_id=workspace_id).select_related("user").afirst()
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
        logger.warning(f"MEMBER_REMOVED: User {email} removed from workspace {workspace_id} by user {request.auth.email}")
        return CustomResponse.success(message=f"Member {email} removed from workspace")

    @route.post("/{workspace_id}/members/{user_id}/role/", response={200: dict, 403: ErrorResponse})
    async def change_member_role(self, request, workspace_id: uuid.UUID, user_id: uuid.UUID, data: MemberRoleActionSchema):
        um = await self._get_membership(request.auth, workspace_id)
        if um.role not in [MembershipRole.ADMIN, MembershipRole.OWNER]:
            raise AuthorizationError("Only admins/owners can change member roles.")
        tm = await Membership.objects.filter(user_id=user_id, workspace_id=workspace_id).select_related("user").afirst()
        if not tm:
            raise NotFoundError("User is not a member of this workspace.")
        if data.action == "demote":
            if tm.role in [MembershipRole.ADMIN, MembershipRole.OWNER]:
                count = await Membership.objects.filter(workspace_id=workspace_id, role__in=[MembershipRole.ADMIN, MembershipRole.OWNER], status=MembershipStatus.ACTIVE).acount()
                if count <= 1:
                    raise BodyValidationError("action", "You are the only admin. Promote another member first.")
            tm.role = MembershipRole.MEMBER
        elif data.action == "promote":
            tm.role = MembershipRole.ADMIN
        await tm.asave()
        return CustomResponse.success(message=f"User is now a {tm.role}", data={"user_id": str(tm.user.id), "role": tm.role})


@api_controller("/workspaces", tags=["Allowlist"], auth=JWTAuth())
class AllowlistController(WorkspaceMixin):

    async def _check_access(self, user, workspace_id):
        m = await Membership.objects.filter(user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE).afirst()
        if not m:
            raise NotFoundError("Workspace not found or no access")
        return m

    @route.get("/{workspace_id}/allowlist/", response={200: dict, 404: ErrorResponse})
    async def list_allowlist(self, request, workspace_id: uuid.UUID):
        await self._check_access(request.auth, workspace_id)
        data = []
        async for e in WorkspaceAllowlist.objects.filter(workspace_id=workspace_id).select_related("added_by"):
            data.append({"id": str(e.id), "domain": e.domain, "added_by_email": e.added_by.email, "added_at": e.added_at.isoformat()})
        return CustomResponse.success(message="Allowlist retrieved", data=data)

    @route.post("/{workspace_id}/allowlist/", response={201: dict, 400: ErrorResponse, 403: ErrorResponse})
    async def bulk_add(self, request, workspace_id: uuid.UUID, data: AllowlistBulkCreateSchema):
        m = await self._check_access(request.auth, workspace_id)
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only admins/owners can manage the allowlist")
        existing = set()
        async for d in WorkspaceAllowlist.objects.filter(workspace_id=workspace_id, domain__in=data.domains).values_list("domain", flat=True):
            existing.add(d)
        new_domains = [d for d in data.domains if d not in existing]
        if not new_domains:
            raise BodyValidationError("domains", "All provided domains are already in the allowlist.")
        entries = await WorkspaceAllowlist.objects.abulk_create([WorkspaceAllowlist(workspace_id=workspace_id, domain=d, added_by=request.auth) for d in new_domains])
        await WorkspaceAllowlistLog.objects.abulk_create([WorkspaceAllowlistLog(workspace_id=workspace_id, domain=d, action="added", performed_by=request.auth) for d in new_domains])
        for e in entries:
            e.added_by = request.auth
        result = [{"id": str(e.id), "domain": e.domain, "added_by_email": e.added_by.email, "added_at": e.added_at.isoformat()} for e in entries]
        return CustomResponse.success(message=f"Added {len(new_domains)} domain(s) to allowlist", data=result, status_code=201)

    @route.delete("/{workspace_id}/allowlist/{domain}/", response={200: SuccessResponse, 403: ErrorResponse, 404: ErrorResponse})
    async def remove_domain(self, request, workspace_id: uuid.UUID, domain: str):
        m = await self._check_access(request.auth, workspace_id)
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only admins/owners can manage the allowlist")
        entry = await WorkspaceAllowlist.objects.filter(workspace_id=workspace_id, domain=domain.lower()).afirst()
        if not entry:
            raise NotFoundError(f"{domain} is not in the allowlist.")
        await entry.adelete()
        await WorkspaceAllowlistLog.objects.acreate(workspace_id=workspace_id, domain=domain.lower(), action="removed", performed_by=request.auth)
        return CustomResponse.success(message="Domain removed from allowlist")

    @route.get("/{workspace_id}/allowlist/log/", response={200: dict, 404: ErrorResponse})
    async def logs(self, request, workspace_id: uuid.UUID):
        await self._check_access(request.auth, workspace_id)
        data = []
        async for log in WorkspaceAllowlistLog.objects.filter(workspace_id=workspace_id).select_related("performed_by"):
            data.append({"domain": log.domain, "action": log.action, "performed_by_email": log.performed_by.email, "performed_at": log.performed_at.isoformat()})
        return CustomResponse.success(message="Logs retrieved", data=data)


@api_controller("/workspaces", tags=["Agents"], auth=JWTAuth())
class AgentController(WorkspaceMixin):

    def _serialize_agent(self, agent):
        last_used = getattr(agent, "last_used_at", None)
        return {
            "id": str(agent.id), "name": agent.name,
            "project_id": str(agent.project_id) if agent.project_id else None,
            "token_count": getattr(agent, "token_count", 0),
            "active_token_count": getattr(agent, "active_token_count", 0),
            "last_used_at": last_used.isoformat() if last_used else None,
            "created_at": agent.created_at.isoformat(),
        }

    async def _check_admin(self, user, workspace_id):
        m = await Membership.objects.filter(user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE).afirst()
        if not m:
            raise NotFoundError("Workspace not found or you don't have access")
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("You don't have permission to manage agents")
        return m

    async def _check_access(self, user, workspace_id):
        m = await Membership.objects.filter(user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE).afirst()
        if not m:
            raise NotFoundError("Workspace not found or you don't have access")
        return m

    async def _create_with_token(self, request, workspace_id, payload, project_id=None):
        await self._check_admin(request.auth, workspace_id)
        kwargs = {"workspace_id": workspace_id, "name": payload.name, "created_by": request.auth}
        if project_id:
            kwargs["project_id"] = project_id
        agent = await AgentRegistration.objects.acreate(**kwargs)
        expires_at = timezone.now() + timezone.timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
        raw_token = secrets_module.token_urlsafe(32)
        token = await AgentToken.objects.acreate(
            registration=agent, workspace_id=workspace_id,
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            label=payload.label, expires_at=expires_at, created_by=request.auth,
        )
        agent_data = self._serialize_agent(agent)
        agent_data["token_count"] = 1
        agent_data["active_token_count"] = 1
        return CustomResponse.success(message="Agent created", data={"agent": agent_data, "token": raw_token, "token_id": str(token.id)}, status_code=201)

    @route.get("/{workspace_id}/agents/", response={200: dict, 404: ErrorResponse})
    async def list_agents(self, request, workspace_id: uuid.UUID):
        await self._check_access(request.auth, workspace_id)
        agents = []
        async for a in AgentRegistration.objects.filter(workspace_id=workspace_id, project__isnull=True).annotate(
            token_count=Count("tokens"), active_token_count=Count("tokens", filter=Q(tokens__revoked_at__isnull=True)),
            last_used_at=Max("tokens__last_used_at"),
        ):
            agents.append(self._serialize_agent(a))
        return CustomResponse.success(message="Agents retrieved", data=agents)

    @route.post("/{workspace_id}/agents/", response={201: dict, 403: ErrorResponse})
    async def create_agent(self, request, workspace_id: uuid.UUID, data: AgentCreateSchema):
        return await self._create_with_token(request, workspace_id, data)

    @route.get("/{workspace_id}/projects/{project_id}/agents/", response={200: dict, 404: ErrorResponse})
    async def list_project_agents(self, request, workspace_id: uuid.UUID, project_id: uuid.UUID):
        await self._check_access(request.auth, workspace_id)
        agents = []
        async for a in AgentRegistration.objects.filter(workspace_id=workspace_id, project_id=project_id).annotate(
            token_count=Count("tokens"), active_token_count=Count("tokens", filter=Q(tokens__revoked_at__isnull=True)),
            last_used_at=Max("tokens__last_used_at"),
        ):
            agents.append(self._serialize_agent(a))
        return CustomResponse.success(message="Project agents retrieved", data=agents)

    @route.post("/{workspace_id}/projects/{project_id}/agents/", response={201: dict, 403: ErrorResponse})
    async def create_project_agent(self, request, workspace_id: uuid.UUID, project_id: uuid.UUID, data: AgentCreateSchema):
        return await self._create_with_token(request, workspace_id, data, project_id)

    @route.get("/{workspace_id}/agents/{registration_id}/", response={200: dict, 404: ErrorResponse})
    async def get_agent(self, request, workspace_id: uuid.UUID, registration_id: str):
        await self._check_access(request.auth, workspace_id)
        agent = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).annotate(
            token_count=Count("tokens"), active_token_count=Count("tokens", filter=Q(tokens__revoked_at__isnull=True)),
            last_used_at=Max("tokens__last_used_at"),
        ).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        return CustomResponse.success(message="Agent retrieved", data=self._serialize_agent(agent))

    @route.delete("/{workspace_id}/agents/{registration_id}/", response={200: SuccessResponse, 403: ErrorResponse})
    async def delete_agent(self, request, workspace_id: uuid.UUID, registration_id: str):
        await self._check_admin(request.auth, workspace_id)
        agent = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        await agent.adelete()
        return CustomResponse.success(message="Agent deleted")

    @route.get("/{workspace_id}/agents/{registration_id}/capabilities/", response={200: dict, 404: ErrorResponse})
    async def get_capabilities(self, request, workspace_id: uuid.UUID, registration_id: str):
        await self._check_access(request.auth, workspace_id)
        agent = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        return CustomResponse.success(message="Capabilities retrieved successfully", data=agent.capabilities or {})

    @route.put("/{workspace_id}/agents/{registration_id}/capabilities/", response={200: dict, 403: ErrorResponse, 404: ErrorResponse})
    async def set_capabilities(self, request, workspace_id: uuid.UUID, registration_id: str, data: AgentCapabilitiesSchema):
        await self._check_admin(request.auth, workspace_id)
        agent = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).afirst()
        if not agent:
            raise NotFoundError("Agent not found")
        agent.capabilities = data.dict()
        await agent.asave()
        return CustomResponse.success(message="Capabilities updated successfully", data=agent.capabilities or {})


@api_controller("/workspaces", tags=["Agent Tokens"], auth=JWTAuth())
class TokenController(WorkspaceMixin):

    async def _check_agent(self, registration_id, workspace_id):
        exists = await AgentRegistration.objects.filter(id=registration_id, workspace_id=workspace_id).aexists()
        if not exists:
            raise NotFoundError("Agent not found")

    async def _check_admin(self, user, workspace_id):
        m = await Membership.objects.filter(user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE).afirst()
        if not m:
            raise NotFoundError("Workspace not found or you don't have access")
        if m.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("You don't have permission to manage tokens")

    @route.get("/{workspace_id}/agents/{registration_id}/tokens/", response={200: dict, 404: ErrorResponse})
    async def list_tokens(self, request, workspace_id: uuid.UUID, registration_id: str):
        await self._check_agent(registration_id, workspace_id)
        data = []
        async for t in AgentToken.objects.filter(registration_id=registration_id):
            data.append({
                "id": str(t.id), "label": t.label,
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
                "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
                "created_at": t.created_at.isoformat(),
            })
        return CustomResponse.success(message="Agent tokens retrieved", data=data)

    @route.post("/{workspace_id}/agents/{registration_id}/tokens/", response={201: dict, 403: ErrorResponse})
    async def create_token(self, request, workspace_id: uuid.UUID, registration_id: str, data: AgentTokenCreateSchema):
        await self._check_agent(registration_id, workspace_id)
        await self._check_admin(request.auth, workspace_id)
        expires_at = timezone.now() + timezone.timedelta(days=data.expires_in_days) if data.expires_in_days else None
        raw_token = secrets_module.token_urlsafe(32)
        token = await AgentToken.objects.acreate(
            registration_id=registration_id, workspace_id=workspace_id,
            token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            label=data.label, expires_at=expires_at, created_by=request.auth,
        )
        return CustomResponse.success(message="Agent token created", data={
            "token": raw_token, "token_id": str(token.id),
            "token_metadata": {"id": str(token.id), "label": token.label, "expires_at": token.expires_at.isoformat() if token.expires_at else None, "created_at": token.created_at.isoformat()},
        }, status_code=201)

    @route.delete("/{workspace_id}/agents/{registration_id}/tokens/", response={200: SuccessResponse, 403: ErrorResponse})
    async def bulk_delete_tokens(self, request, workspace_id: uuid.UUID, registration_id: str):
        await self._check_agent(registration_id, workspace_id)
        await self._check_admin(request.auth, workspace_id)
        await AgentToken.objects.filter(registration_id=registration_id).adelete()
        return CustomResponse.success(message="All tokens deleted")

    @route.delete("/{workspace_id}/agents/{registration_id}/tokens/{token_id}/", response={200: SuccessResponse, 404: ErrorResponse})
    async def delete_token(self, request, workspace_id: uuid.UUID, registration_id: str, token_id: str):
        await self._check_agent(registration_id, workspace_id)
        await self._check_admin(request.auth, workspace_id)
        token = await AgentToken.objects.filter(id=token_id, registration_id=registration_id).afirst()
        if not token:
            raise NotFoundError("Token not found")
        await token.adelete()
        return CustomResponse.success(message="Token deleted")


@api_controller("/audit", tags=["Audit Logs"], auth=JWTAuth())
class AuditController(WorkspaceMixin):

    def _apply_filters(self, qs, request):
        simple = {"project_id": "project_id", "agent_id": "agent_id", "agent_token_id": "agent_token_id",
                   "identity_level": "identity_level", "credential_ref": "credential_ref",
                   "environment": "environment", "resolution_path": "resolution_path"}
        for param, field in simple.items():
            val = request.GET.get(param)
            if val:
                qs = qs.filter(**{field: val})
        domain = request.GET.get("domain")
        if domain:
            qs = qs.filter(target_domain__icontains=domain)
        method = request.GET.get("method")
        if method:
            qs = qs.filter(method=method.upper())
        status_code = request.GET.get("status_code")
        if status_code:
            qs = qs.filter(status_code=status_code)
        since = request.GET.get("since")
        if since:
            qs = qs.filter(timestamp__gte=since)
        until = request.GET.get("until")
        if until:
            qs = qs.filter(timestamp__lte=until)
        return qs

    async def _check_ws(self, user, workspace_id):
        m = await Membership.objects.filter(user=user, workspace_id=workspace_id, status=MembershipStatus.ACTIVE).afirst()
        if not m:
            raise NotFoundError("Workspace not found or you don't have access")

    @route.get("/logs/", response={200: dict, 400: ErrorResponse})
    async def list_logs(self, request, workspace_id: str = None, limit: int = 100):
        if not workspace_id:
            raise BodyValidationError("workspace_id", "workspace_id is required")
        await self._check_ws(request.auth, workspace_id)
        qs = self._apply_filters(AuditLogEntry.objects.filter(workspace_id=workspace_id), request)
        limit = max(1, min(limit, 1000))
        fields = [
            "id", "timestamp", "agent_id", "identity_level", "credential_ref",
            "injection_style", "target_domain", "target_url", "method",
            "status_code", "duration_ms", "redacted", "resolution_path", "error"
        ]
        logs = qs.order_by("-timestamp").values(*fields)[:limit]
        data = [
            {
                "id": str(log["id"]), "timestamp": log["timestamp"].isoformat() if log["timestamp"] else None,
                "agent_id": log["agent_id"], "identity_level": log["identity_level"],
                "credential_ref": log["credential_ref"], "injection_style": log["injection_style"],
                "target_domain": log["target_domain"], "target_url": log["target_url"],
                "method": log["method"], "status_code": log["status_code"],
                "duration_ms": log["duration_ms"], "redacted": log["redacted"],
                "resolution_path": log["resolution_path"], "error": log["error"],
            }
            async for log in logs
        ]
        return CustomResponse.success(message="Audit logs retrieved", data=data)

    @route.get("/logs/{log_id}/", response={200: dict, 404: ErrorResponse})
    async def detail(self, request, log_id: str):
        log = await AuditLogEntry.objects.filter(id=log_id).afirst()
        if not log:
            raise NotFoundError("Log not found")
        await self._check_ws(request.auth, log.workspace_id)
        fields = {}
        for f in log._meta.get_fields():
            if hasattr(f, "attname"):
                val = getattr(log, f.attname)
                if hasattr(val, "isoformat"):
                    val = val.isoformat()
                elif not isinstance(val, (str, int, float, bool, type(None))):
                    val = str(val)
                fields[f.attname] = val
        return CustomResponse.success(message="Audit log detail retrieved", data=fields)

    @route.get("/summary/", response={200: dict, 400: ErrorResponse})
    async def summary(self, request, workspace_id: str = None):
        if not workspace_id:
            raise BodyValidationError("workspace_id", "workspace_id is required")
        await self._check_ws(request.auth, workspace_id)
        qs = AuditLogEntry.objects.filter(workspace_id=workspace_id)
        start = request.GET.get("start")
        end = request.GET.get("end")
        if start:
            qs = qs.filter(timestamp__gte=start)
        if end:
            qs = qs.filter(timestamp__lte=end)
        total_requests = await qs.acount()
        total_errors = await qs.filter(status_code__gte=400).acount()
        by_agent = await sync_to_async(list)(qs.exclude(agent_id__isnull=True).exclude(agent_id="").values("agent_id").annotate(
            count=Count("id"), failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
        ).order_by("-count"))
        by_domain = await sync_to_async(list)(qs.values("target_domain").annotate(
            count=Count("id"), failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
        ).order_by("-count"))
        by_credential = await sync_to_async(list)(qs.values("credential_ref").annotate(
            count=Count("id"), failed=Count("id", filter=Q(status_code__gte=400) | Q(error__isnull=False)),
        ).order_by("-count"))
        anon_count = await qs.filter(identity_level=IdentityLevel.ANONYMOUS).acount()
        return CustomResponse.success(message="Audit log summary retrieved", data={
            "period": {"start": start or "all", "end": end or "all"},
            "totals": {"requests": total_requests, "errors": total_errors},
            "by_agent": [{"agent_id": r["agent_id"], "count": r["count"], "failed": r["failed"]} for r in by_agent],
            "by_credential": [{"credential_ref": r["credential_ref"], "count": r["count"], "failed": r["failed"]} for r in by_credential],
            "by_domain": [{"domain": r["target_domain"], "count": r["count"], "failed": r["failed"]} for r in by_domain],
            "anonymous_call_count": anon_count,
        })

    @route.get("/export/", response={200: dict, 400: ErrorResponse})
    async def export(self, request, workspace_id: str = None):
        if not workspace_id:
            raise BodyValidationError("workspace_id", "workspace_id is required")
        await self._check_ws(request.auth, workspace_id)
        fmt = request.GET.get("format", "jsonl").lower()
        if fmt != "jsonl":
            raise BodyValidationError("format", "Unsupported format. Only 'jsonl' is supported.")
        qs = self._apply_filters(AuditLogEntry.objects.filter(workspace_id=workspace_id), request)

        def generate_jsonl():
            for log in qs.order_by("-timestamp"):
                fields = {}
                for f in log._meta.get_fields():
                    if hasattr(f, "attname"):
                        val = getattr(log, f.attname)
                        if hasattr(val, "isoformat"):
                            val = val.isoformat()
                        elif not isinstance(val, (str, int, float, bool, type(None))):
                            val = str(val)
                        fields[f.attname] = val
                yield json.dumps(fields) + "\n"

        response = StreamingHttpResponse(generate_jsonl(), content_type="application/x-ndjson")
        response["Content-Disposition"] = f'attachment; filename="audit_log_export_{workspace_id}.jsonl"'
        return response


@api_controller("/internal", tags=["Internal"])
class ResolverController:
    """
    Internal endpoints for the resolver service.
    Authenticated via RESOLVER_SERVICE_KEY — not user session auth.
    """

    @route.post("/agents/verify/", response={200: dict}, auth=InternalOrUserAuth())
    async def verify_agent(self, request, data: InternalAgentVerifySchema):
        token = await AgentToken.objects.select_related("registration").filter(id=data.token_id).afirst()
        if not token:
            return {"valid": False, "reason": "Not found"}

        if isinstance(request.auth, User):
            has_access = await Membership.objects.filter(
                user=request.auth, workspace_id=token.workspace_id, status=MembershipStatus.ACTIVE
            ).aexists()
            if not has_access:
                return {"valid": False, "reason": "Unauthorized workspace access"}

        token_hash = hashlib.sha256(data.token.encode()).hexdigest()
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
            "valid": True, "agent_id": str(agent.id), "agent_name": agent.name,
            "workspace_id": str(token.workspace_id), "project_id": str(agent.project_id) if agent.project_id else None,
            "environment": token.environment,
            "capabilities": agent.capabilities or {},
        }

    @route.post("/audit/logs/", response={201: dict, 401: dict, 429: dict}, auth=None)
    async def create_audit_logs(self, request):
        from django.core.cache import cache
        from apps.common.auth import InternalOrUserAuth
        from asgiref.sync import sync_to_async

        ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', 'unknown')).split(',')[0].strip()
        
        # 1. Strict rate limit for unauthenticated/failed auth attempts
        unauth_key = f"rl_unauth_audit_{ip}"
        unauth_count = cache.get(unauth_key, 0)
        if unauth_count >= 50:
            return 429, {"detail": "Rate limit exceeded (Max 50/day for unauthenticated requests)"}

        # 2. Extract and check authentication manually
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        token = auth_header[7:] if auth_header.startswith('Bearer ') else None
        
        user = await sync_to_async(InternalOrUserAuth().authenticate)(request, token) if token else None
        if not user:
            # Increment unauth counter and reject
            cache.set(unauth_key, unauth_count + 1, timeout=86400)
            return 401, {"detail": "Unauthorized"}
            
        request.auth = user

        # 3. Rate limit for authenticated successful requests
        key = f"rl_audit_{ip}"
        count = cache.get(key, 0)
        if count >= 3000:
            return 429, {"detail": "Rate limit exceeded (Max 3000/day)"}
        cache.set(key, count + 1, timeout=86400)

        body = json.loads(request.body)
        entries = body if isinstance(body, list) else [body]

        def map_entry(e):
            """Map CLI AuditEvent JSON fields to AuditLogEntry model fields."""
            mapped = {}

            # Direct 1:1 mappings
            direct_fields = [
                'id', 'schema_version', 'timestamp', 'environment',
                'agent_id', 'identity_level', 'method', 'target_url',
                'target_path', 'status_code', 'duration_ms', 'proxy_duration_ms',
                'redacted', 'redaction_reason', 'resolution_path',
                'allowlist_snapshot', 'caller_role', 'session_id',
                'policy_snapshot_id', 'error', 'credential_ref', 'injection_style',
                'target_domain',
            ]
            for field in direct_fields:
                if field in e:
                    mapped[field] = e[field]

            # CLI sends 'domain' but model uses 'target_domain'
            if 'domain' in e and 'target_domain' not in mapped:
                mapped['target_domain'] = e['domain']

            # FK references: CLI sends string IDs, model expects _id suffix
            if 'workspace_id' in e and 'workspace' not in e:
                mapped['workspace_id'] = e['workspace_id']
            if 'project_id' in e and 'project' not in e:
                mapped['project_id'] = e['project_id']
            if 'token_id' in e and 'agent_token' not in e:
                mapped['agent_token_id'] = e['token_id']

            return mapped

        model_entries = [AuditLogEntry(**map_entry(e)) for e in entries]
        created = await AuditLogEntry.objects.abulk_create(model_entries)
        return 201, {"created_count": len(created), "ids": [str(log.id) for log in created]}
