import json
import logging
import uuid
from typing import Any, List, Dict
from django.core.cache import cache
from django.http import StreamingHttpResponse
from asgiref.sync import sync_to_async
from ninja_extra import api_controller, route

from apps.accounts.models import User
from apps.accounts.auth import JWTAuth, InternalOrUserAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse, DataResponse
from apps.common.exceptions import BodyValidationError
from .schemas import (
    WorkspaceCreateSchema,
    WorkspaceUpdateSchema,
    MemberUpdateSchema,
    MemberRoleActionSchema,
    InviteEntrySchema,
    BatchInviteSchema,
    AllowlistBulkCreateSchema,
    AgentCreateSchema,
    AgentTokenCreateSchema,
    AgentCapabilitiesSchema,
    InternalAgentVerifySchema,
    WorkspaceItemSchema,
    WorkspaceDetailSchema,
    WorkspaceSimpleSchema,
    MemberItemSchema,
    InviteResultItemSchema,
    MemberRoleUpdateResponseSchema,
    AllowlistItemSchema,
    AllowlistLogItemSchema,
    AgentItemSchema,
    AgentCreatedResponseDataSchema,
    AgentTokenItemSchema,
    AgentTokenCreatedResponseDataSchema,
    AgentVerifyResponseSchema,
    AuditLogItemSchema,
    AuditSummaryResponseSchema,
    WorkspaceActivityItemSchema,
    ForensicDecisionReplaySchema,
)
from .selectors import (
    WorkspaceSelector,
    AllowlistSelector,
    AgentSelector,
    AuditSelector,
    ActivityLogSelector,
    ForensicLogSelector,
)
from .services import (
    WorkspaceService,
    MemberService,
    AllowlistService,
    AgentService,
    WorkloadService,
    ActivityLogService,
    ForensicLogService,
)

logger = logging.getLogger("apps.workspaces")


@api_controller("/workspaces", tags=["Workspaces"], auth=JWTAuth())
class WorkspaceController:
    """
    Workspace lifecycle and membership management controllers.
    """

    @route.get("/", response={200: DataResponse[List[WorkspaceItemSchema]]})
    async def list_workspaces(self, request):
        data = await WorkspaceSelector.list_user_workspaces(user=request.auth)
        return CustomResponse.success(message="Workspaces retrieved successfully", data=data)

    @route.post("/", response={201: DataResponse[WorkspaceSimpleSchema]})
    async def create_workspace(self, request, data: WorkspaceCreateSchema):
        result = await WorkspaceService.create_workspace(user=request.auth, data=data)
        return CustomResponse.success(message="Workspace created successfully", data=result, status_code=201)

    @route.get("/{workspace_id}/", response={200: DataResponse[WorkspaceDetailSchema], 404: ErrorResponse})
    async def get_workspace(self, request, workspace_id: uuid.UUID):
        m = await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        ws = m.workspace
        return CustomResponse.success(
            message="Workspace retrieved successfully",
            data={
                "id": str(ws.id),
                "name": ws.name,
                "type": ws.type,
                "role": m.role,
                "billing_id": ws.billing_id,
                "encrypted_workspace_key": m.encrypted_workspace_key,
                "created_at": ws.created_at.isoformat(),
                "updated_at": ws.updated_at.isoformat(),
            },
        )

    @route.post("/{workspace_id}/billing/initialize/", response={200: DataResponse[Dict[str, Any]], 403: ErrorResponse})
    async def initialize_workspace_billing(self, request, workspace_id: uuid.UUID):
        billing_id = await WorkspaceService.initialize_workspace_billing(user=request.auth, workspace_id=workspace_id)
        return CustomResponse.success(message="Workspace billing initialized successfully", data={"billing_id": billing_id})

    @route.patch("/{workspace_id}/", response={200: DataResponse[WorkspaceSimpleSchema], 403: ErrorResponse})
    async def update_workspace(self, request, workspace_id: uuid.UUID, data: WorkspaceUpdateSchema):
        result = await WorkspaceService.update_workspace(
            user=request.auth, workspace_id=workspace_id, data=data
        )
        return CustomResponse.success(message="Workspace updated successfully", data=result)

    @route.delete("/{workspace_id}/", response={200: SuccessResponse, 403: ErrorResponse})
    async def delete_workspace(self, request, workspace_id: uuid.UUID):
        name = await WorkspaceService.delete_workspace(user=request.auth, workspace_id=workspace_id)
        return CustomResponse.success(message=f"Workspace '{name}' deleted successfully")

    @route.get("/{workspace_id}/activity/", response={200: DataResponse[List[WorkspaceActivityItemSchema]], 403: ErrorResponse, 404: ErrorResponse})
    async def list_activity(self, request, workspace_id: uuid.UUID, limit: int = 100, offset: int = 0):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        params = request.GET.dict()
        data = await ActivityLogSelector.list_activity(
            workspace_id=workspace_id,
            params=params,
            limit=limit,
            offset=offset,
        )
        return CustomResponse.success(message="Workspace activity logs retrieved successfully", data=data)

    # --- Members ---

    @route.get("/{workspace_id}/members/", response={200: DataResponse[List[MemberItemSchema]], 404: ErrorResponse})
    async def list_members(self, request, workspace_id: uuid.UUID):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        members = await WorkspaceSelector.list_workspace_members(workspace_id=workspace_id)
        return CustomResponse.success(message="Members retrieved successfully", data=members)

    @route.post("/{workspace_id}/members/", response={201: DataResponse[List[InviteResultItemSchema]], 200: DataResponse[List[InviteResultItemSchema]], 403: ErrorResponse, 404: ErrorResponse, 422: ErrorResponse})
    async def invite_member(self, request, workspace_id: uuid.UUID, data: dict = None):
        try:
            body = json.loads(request.body)
            if "invites" in body:
                parsed = BatchInviteSchema(**body)
                entries = parsed.invites
            else:
                entry = InviteEntrySchema(**body)
                entries = [entry]
        except Exception as e:
            return CustomResponse.error(
                message=f"Invalid invite request: {str(e)}",
                status_code=422,
            )

        results, any_created = await MemberService.process_member_invites(
            user=request.auth, workspace_id=workspace_id, entries=entries
        )
        status_code = 201 if any_created else 200
        return CustomResponse.success(
            message="Invites processed",
            data=results,
            status_code=status_code,
        )

    @route.patch("/{workspace_id}/members/{user_id}/", response={200: DataResponse[MemberRoleUpdateResponseSchema], 403: ErrorResponse, 404: ErrorResponse})
    async def update_member(self, request, workspace_id: uuid.UUID, user_id: uuid.UUID, data: MemberUpdateSchema):
        result = await MemberService.update_member_role(
            user=request.auth, workspace_id=workspace_id, target_user_id=user_id, role=data.role
        )
        return CustomResponse.success(message=f"Member role updated to {data.role}", data=result)

    @route.delete("/{workspace_id}/members/{user_id}/", response={200: SuccessResponse, 403: ErrorResponse})
    async def remove_member(self, request, workspace_id: uuid.UUID, user_id: uuid.UUID):
        email = await MemberService.remove_member(
            user=request.auth, workspace_id=workspace_id, target_user_id=user_id
        )
        return CustomResponse.success(message=f"Member {email} removed from workspace")

    @route.post("/{workspace_id}/members/{user_id}/role/", response={200: DataResponse[MemberRoleUpdateResponseSchema], 403: ErrorResponse})
    async def change_member_role(self, request, workspace_id: uuid.UUID, user_id: uuid.UUID, data: MemberRoleActionSchema):
        result = await MemberService.change_member_role_action(
            user=request.auth, workspace_id=workspace_id, target_user_id=user_id, action=data.action
        )
        return CustomResponse.success(message=f"User is now a {result['role']}", data=result)


@api_controller("/workspaces", tags=["Allowlist"], auth=JWTAuth())
class AllowlistController:
    """
    Workspace proxy outbound domain allowlist controllers.
    """

    @route.get("/{workspace_id}/allowlist/", response={200: DataResponse[List[AllowlistItemSchema]], 404: ErrorResponse})
    async def list_allowlist(self, request, workspace_id: uuid.UUID):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        data = await AllowlistSelector.list_allowlist(workspace_id=workspace_id)
        return CustomResponse.success(message="Allowlist retrieved", data=data)

    @route.post("/{workspace_id}/allowlist/", response={201: DataResponse[List[AllowlistItemSchema]], 400: ErrorResponse, 403: ErrorResponse})
    async def bulk_add(self, request, workspace_id: uuid.UUID, data: AllowlistBulkCreateSchema):
        result = await AllowlistService.bulk_add_domains(
            user=request.auth, workspace_id=workspace_id, domains=data.domains
        )
        return CustomResponse.success(
            message=f"Added {len(data.domains)} domain(s) to allowlist",
            data=result,
            status_code=201,
        )

    @route.get("/{workspace_id}/allowlist/log/", response={200: DataResponse[List[AllowlistLogItemSchema]], 404: ErrorResponse})
    async def logs(self, request, workspace_id: uuid.UUID):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        data = await AllowlistSelector.list_allowlist_logs(workspace_id=workspace_id)
        return CustomResponse.success(message="Logs retrieved", data=data)

    @route.delete("/{workspace_id}/allowlist/{domain}/", response={200: SuccessResponse, 403: ErrorResponse, 404: ErrorResponse})
    async def remove_domain(self, request, workspace_id: uuid.UUID, domain: str):
        await AllowlistService.remove_domain(
            user=request.auth, workspace_id=workspace_id, domain=domain
        )
        return CustomResponse.success(message="Domain removed from allowlist")


@api_controller("/workspaces", tags=["Agents"], auth=JWTAuth())
class AgentController:
    """
    AI Agent registration and token lifecycle controllers.
    """

    @route.get("/{workspace_id}/agents/", response={200: DataResponse[List[AgentItemSchema]], 404: ErrorResponse})
    async def list_agents(self, request, workspace_id: uuid.UUID, include_projects: bool = False):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        agents = await AgentSelector.list_agents(
            workspace_id=workspace_id, include_projects=include_projects
        )
        return CustomResponse.success(message="Agents retrieved", data=agents)

    @route.post("/{workspace_id}/agents/", response={201: DataResponse[AgentCreatedResponseDataSchema], 403: ErrorResponse})
    async def create_agent(self, request, workspace_id: uuid.UUID, data: AgentCreateSchema):
        agent_data, raw_token, token_id = await AgentService.create_agent_with_token(
            user=request.auth, workspace_id=workspace_id, payload=data
        )
        return CustomResponse.success(
            message="Agent created",
            data={"agent": agent_data, "token": raw_token, "token_id": token_id},
            status_code=201,
        )

    @route.get("/{workspace_id}/projects/{project_id}/agents/", response={200: DataResponse[List[AgentItemSchema]], 404: ErrorResponse})
    async def list_project_agents(self, request, workspace_id: uuid.UUID, project_id: uuid.UUID):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        agents = await AgentSelector.list_agents(
            workspace_id=workspace_id, project_id=project_id, include_projects=True
        )
        return CustomResponse.success(message="Project agents retrieved", data=agents)

    @route.post("/{workspace_id}/projects/{project_id}/agents/", response={201: DataResponse[AgentCreatedResponseDataSchema], 403: ErrorResponse})
    async def create_project_agent(self, request, workspace_id: uuid.UUID, project_id: uuid.UUID, data: AgentCreateSchema):
        agent_data, raw_token, token_id = await AgentService.create_agent_with_token(
            user=request.auth, workspace_id=workspace_id, payload=data, project_id=project_id
        )
        return CustomResponse.success(
            message="Agent created",
            data={"agent": agent_data, "token": raw_token, "token_id": token_id},
            status_code=201,
        )

    @route.get("/{workspace_id}/agents/{registration_id}/", response={200: DataResponse[AgentItemSchema], 404: ErrorResponse})
    async def get_agent(self, request, workspace_id: uuid.UUID, registration_id: str):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        agent = await AgentSelector.get_agent_by_id(workspace_id=workspace_id, registration_id=registration_id)
        return CustomResponse.success(message="Agent retrieved", data=agent)

    @route.delete("/{workspace_id}/agents/{registration_id}/", response={200: SuccessResponse, 403: ErrorResponse})
    async def delete_agent(self, request, workspace_id: uuid.UUID, registration_id: str):
        await AgentService.delete_agent(
            user=request.auth, workspace_id=workspace_id, registration_id=registration_id
        )
        return CustomResponse.success(message="Agent deleted")

    @route.get("/{workspace_id}/agents/{registration_id}/capabilities/", response={200: DataResponse[Dict[str, Any]], 404: ErrorResponse})
    async def get_capabilities(self, request, workspace_id: uuid.UUID, registration_id: str):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        caps = await AgentSelector.get_agent_capabilities(
            workspace_id=workspace_id, registration_id=registration_id
        )
        return CustomResponse.success(message="Capabilities retrieved successfully", data=caps)

    @route.put("/{workspace_id}/agents/{registration_id}/capabilities/", response={200: DataResponse[Dict[str, Any]], 403: ErrorResponse, 404: ErrorResponse})
    async def set_capabilities(self, request, workspace_id: uuid.UUID, registration_id: str, data: AgentCapabilitiesSchema):
        caps = await AgentService.update_agent_capabilities(
            user=request.auth,
            workspace_id=workspace_id,
            registration_id=registration_id,
            capabilities=data.dict(),
        )
        return CustomResponse.success(message="Capabilities updated successfully", data=caps)


@api_controller("/workspaces", tags=["Agent Tokens"], auth=JWTAuth())
class TokenController:
    """
    Agent authentication token issuance and revocation controllers.
    """

    @route.get("/{workspace_id}/agents/{registration_id}/tokens/", response={200: DataResponse[List[AgentTokenItemSchema]], 404: ErrorResponse})
    async def list_tokens(self, request, workspace_id: uuid.UUID, registration_id: str):
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=workspace_id)
        data = await AgentSelector.list_agent_tokens(
            workspace_id=workspace_id, registration_id=registration_id
        )
        return CustomResponse.success(message="Agent tokens retrieved", data=data)

    @route.post("/{workspace_id}/agents/{registration_id}/tokens/", response={201: DataResponse[AgentTokenCreatedResponseDataSchema], 403: ErrorResponse})
    async def create_token(self, request, workspace_id: uuid.UUID, registration_id: str, data: AgentTokenCreateSchema):
        raw_token, token_id, metadata = await AgentService.create_agent_token(
            user=request.auth, workspace_id=workspace_id, registration_id=registration_id, data=data
        )
        return CustomResponse.success(
            message="Agent token created",
            data={
                "token": raw_token,
                "token_id": token_id,
                "token_metadata": metadata,
            },
            status_code=201,
        )

    @route.delete("/{workspace_id}/agents/{registration_id}/tokens/", response={200: SuccessResponse, 403: ErrorResponse})
    async def bulk_delete_tokens(self, request, workspace_id: uuid.UUID, registration_id: str):
        await AgentService.bulk_delete_agent_tokens(
            user=request.auth, workspace_id=workspace_id, registration_id=registration_id
        )
        return CustomResponse.success(message="All tokens deleted")

    @route.delete("/{workspace_id}/agents/{registration_id}/tokens/{token_id}/", response={200: SuccessResponse, 404: ErrorResponse})
    async def delete_token(self, request, workspace_id: uuid.UUID, registration_id: str, token_id: str):
        await AgentService.delete_agent_token(
            user=request.auth,
            workspace_id=workspace_id,
            registration_id=registration_id,
            token_id=token_id,
        )
        return CustomResponse.success(message="Token deleted")


@api_controller("/audit", tags=["Audit Logs"], auth=JWTAuth())
class AuditController:
    """
    Audit logging analysis and export controllers.
    """

    @route.get("/logs/", response={200: DataResponse[List[AuditLogItemSchema]], 400: ErrorResponse})
    async def list_logs(self, request, workspace_id: str = None, limit: int = 100):
        if not workspace_id:
            raise BodyValidationError("workspace_id", "workspace_id is required")
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=uuid.UUID(workspace_id))
        params = request.GET.dict()
        data = await AuditSelector.list_audit_logs(workspace_id=workspace_id, params=params, limit=limit)
        return CustomResponse.success(message="Audit logs retrieved", data=data)

    @route.get("/logs/{log_id}/", response={200: DataResponse[Dict[str, Any]], 404: ErrorResponse})
    async def detail(self, request, log_id: str):
        fields = await AuditSelector.get_audit_log_detail(log_id=log_id, user=request.auth)
        return CustomResponse.success(message="Audit log detail retrieved", data=fields)

    @route.get("/summary/", response={200: DataResponse[AuditSummaryResponseSchema], 400: ErrorResponse})
    async def summary(self, request, workspace_id: str = None):
        if not workspace_id:
            raise BodyValidationError("workspace_id", "workspace_id is required")
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=uuid.UUID(workspace_id))
        start = request.GET.get("start")
        end = request.GET.get("end")
        data = await AuditSelector.get_audit_log_summary(workspace_id=workspace_id, start=start, end=end)
        return CustomResponse.success(message="Audit log summary retrieved", data=data)

    @route.get("/export/", response={200: dict, 400: ErrorResponse})
    async def export(self, request, workspace_id: str = None):
        if not workspace_id:
            raise BodyValidationError("workspace_id", "workspace_id is required")
        await WorkspaceSelector.get_membership(user=request.auth, workspace_id=uuid.UUID(workspace_id))
        fmt = request.GET.get("format", "jsonl").lower()
        if fmt != "jsonl":
            raise BodyValidationError("format", "Unsupported format. Only 'jsonl' is supported.")

        from .models import AuditLogEntry, IdentityLevel
        qs = AuditSelector.apply_filters(
            AuditLogEntry.objects.filter(workspace_id=workspace_id).exclude(identity_level=IdentityLevel.USER),
            request.GET.dict(),
        )

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
    Internal endpoints for the resolver proxy service.
    Authenticated via RESOLVER_SERVICE_KEY or user session auth.
    """

    @route.post("/agents/verify/", response={200: AgentVerifyResponseSchema, 401: ErrorResponse}, auth=None)
    async def verify_agent(self, request):
        try:
            body = json.loads(request.body) if request.body else {}
        except Exception:
            body = {}

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        bearer_token = auth_header[7:] if auth_header.startswith("Bearer ") else None

        token_val = body.get("token") or bearer_token or ""
        token_id = body.get("token_id")

        payload = InternalAgentVerifySchema(
            token=token_val,
            token_id=token_id,
        )
        auth_caller = getattr(request, "auth", None)
        result = await AgentService.verify_agent_token(auth_caller=auth_caller, data=payload)
        return result

    @route.post("/audit/logs/", response={201: dict, 401: dict, 429: dict}, auth=None)
    async def create_audit_logs(self, request):
        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown")).split(",")[0].strip()

        # 1. Extract and check authentication
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else None

        user = None
        agent_token_auth = None

        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            user = request.user
        elif token:
            user = await sync_to_async(InternalOrUserAuth().authenticate)(request, token)
            if not user:
                # Workload Token Delegation: check if Bearer token is an active AgentToken
                import hashlib
                from .models import AgentToken
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                agent_token_auth = await AgentToken.objects.select_related("workspace").filter(
                    token_hash=token_hash,
                    revoked_at__isnull=True
                ).afirst()

        if not user and not agent_token_auth:
            unauth_key = f"rl_unauth_audit_{ip}"
            unauth_count = cache.get(unauth_key, 0)
            cache.set(unauth_key, unauth_count + 1, timeout=86400)
            return 401, {"detail": "Unauthorized: valid service key or agent token required"}

        request.auth = user or agent_token_auth

        # 2. Rate limit for authenticated requests (up to 50,000 logs/day per IP)
        key = f"rl_audit_{ip}"
        count = cache.get(key, 0)
        if count >= 50000:
            return 429, {"detail": "Rate limit exceeded"}
        cache.set(key, count + 1, timeout=86400)

        body = json.loads(request.body)
        entries = body if isinstance(body, list) else [body]

        # If authenticated via agent_token, enforce that entries belong to that workspace
        if agent_token_auth:
            auth_ws_id = str(agent_token_auth.workspace_id)
            entries = [e for e in entries if str(e.get("workspace_id")) == auth_ws_id]

        created_count, ids = await AgentService.ingest_audit_logs(entries=entries)
        return 201, {"created_count": created_count, "ids": ids}

    @route.post("/forensic/logs/", response={201: dict, 401: dict, 429: dict}, auth=None)
    async def create_forensic_logs(self, request):
        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown")).split(",")[0].strip()

        # 1. Extract and check authentication
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else None

        user = None
        agent_token_auth = None

        if hasattr(request, "user") and request.user and request.user.is_authenticated:
            user = request.user
        elif token:
            user = await sync_to_async(InternalOrUserAuth().authenticate)(request, token)
            if not user:
                import hashlib
                from .models import AgentToken
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                agent_token_auth = await AgentToken.objects.select_related("workspace").filter(
                    token_hash=token_hash,
                    revoked_at__isnull=True
                ).afirst()

        if not user and not agent_token_auth:
            unauth_key = f"rl_unauth_forensic_{ip}"
            unauth_count = cache.get(unauth_key, 0)
            cache.set(unauth_key, unauth_count + 1, timeout=86400)
            return 401, {"detail": "Unauthorized: valid service key or agent token required"}

        request.auth = user or agent_token_auth

        # 2. Rate limit for authenticated requests (up to 50,000 logs/day per IP)
        key = f"rl_forensic_{ip}"
        count = cache.get(key, 0)
        if count >= 50000:
            return 429, {"detail": "Rate limit exceeded"}
        cache.set(key, count + 1, timeout=86400)

        body = json.loads(request.body)
        entries = body if isinstance(body, list) else [body]

        # If authenticated via agent_token, enforce that entries belong to that workspace
        if agent_token_auth:
            auth_ws_id = str(agent_token_auth.workspace_id)
            entries = [e for e in entries if str(e.get("workspace_id")) == auth_ws_id]

        created_count, ids = await ForensicLogService.ingest_forensic_logs(entries=entries)
        return 201, {"created_count": created_count, "ids": ids}


@api_controller("/workloads", tags=["Workloads"])
class WorkloadController:
    """
    Headless container and production workload secret injection endpoint.
    """

    @route.post("/env/", response={200: DataResponse[dict], 401: ErrorResponse}, auth=None)
    async def get_workload_env(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else None
        if not token:
            return 401, {"detail": "Missing Authorization: Bearer <agent_token>"}

        body = json.loads(request.body) if request.body else {}
        env_override = body.get("env")

        data = await WorkloadService.deliver_env_secrets(raw_token=token, env_override=env_override)
        return CustomResponse.success(message="Environment secrets resolved successfully", data=data)


@api_controller("/workspaces/{workspace_id}/delegation", tags=["Delegation"], auth=JWTAuth())
class DelegationController:
    """
    Cloud Environment Delegation Key (CEDK) management controllers.
    """

    @route.get("/", response={200: DataResponse[dict], 404: ErrorResponse})
    async def get_delegation(self, request, workspace_id: uuid.UUID):
        data = await CloudDelegationSelector.get_delegation_info(user=request.auth, workspace_id=workspace_id)
        return CustomResponse.success(message="Delegation info retrieved", data=data)

    @route.post("/", response={200: DataResponse[dict], 403: ErrorResponse})
    async def save_delegation(self, request, workspace_id: uuid.UUID):
        body = json.loads(request.body)
        data = await CloudDelegationService.save_delegation(
            user=request.auth,
            workspace_id=workspace_id,
            resolver_name=body.get("resolver_name", "default"),
            public_key=body["public_key"],
            sealed_workspace_key=body["sealed_workspace_key"],
        )
        return CustomResponse.success(message="Delegation saved successfully", data=data)

    @route.delete("/", response={200: SuccessResponse, 403: ErrorResponse})
    async def revoke_delegation(self, request, workspace_id: uuid.UUID):
        await CloudDelegationService.revoke_delegation(user=request.auth, workspace_id=workspace_id)
        return CustomResponse.success(message="Delegation revoked successfully")


@api_controller("/forensic", tags=["Forensic"], auth=JWTAuth())
class ForensicController:
    """
    Forensic log querying and cryptographic session replay controllers (Tier 3).
    """

    @route.get("/logs/{log_id}/replay/", response={200: DataResponse[ForensicDecisionReplaySchema], 403: ErrorResponse, 404: ErrorResponse})
    async def replay_log(self, request, log_id: str):
        data = await ForensicLogSelector.get_replay(log_id=log_id, user=request.auth)
        return CustomResponse.success(message="Forensic decision replay retrieved successfully", data=data)

