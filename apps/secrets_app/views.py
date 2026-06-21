# Standard library
import uuid

# Django
from django.db.models import Count
from asgiref.sync import sync_to_async

import logging
from ninja_extra import api_controller, route
from ninja import Body



logger = logging.getLogger("apps.secrets_app")

# Local
from apps.common.auth import JWTAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse
from apps.common.exceptions import NotFoundError, AuthorizationError, BodyValidationError
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.accounts.models import User
from apps.workspaces.models import (
    Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus,
)
from .mixins import ProjectsMixin, SecretsMixin
from .models import Project, Secret
from .schemas import (
    ProjectCreateSchema, ProjectUpdateSchema, ProjectInviteSchema,
    SecretBulkUpsertSchema, SecretUpdateSchema,
)


@api_controller("/projects", tags=["Projects"], auth=JWTAuth())
class ProjectController(ProjectsMixin):

    async def _resolve_project(self, user, project_name, workspace_id=None):
        name = project_name.lower()
        if workspace_id:
            project = await Project.objects.select_related("workspace").filter(
                name=name,
                workspace_id=workspace_id,
                workspace__memberships__user=user,
                workspace__memberships__status=MembershipStatus.ACTIVE
            ).afirst()
            if not project:
                if await Project.objects.filter(name=name, workspace_id=workspace_id).aexists():
                    raise AuthorizationError("You don't have access to this workspace")
                raise NotFoundError("Project not found")
        else:
            project = await Project.objects.select_related("workspace").filter(
                name=name,
                workspace__memberships__user=user,
                workspace__memberships__status=MembershipStatus.ACTIVE
            ).afirst()
            if not project:
                raise NotFoundError("Project not found")
        return project

    async def _resolve_project_by_id(self, user, project_id):
        project = await Project.objects.select_related("workspace").filter(id=project_id).afirst()
        if not project:
            raise NotFoundError("Project not found")
        exists = await Membership.objects.filter(user=user, workspace=project.workspace, status=MembershipStatus.ACTIVE).aexists()
        if not exists:
            raise AuthorizationError("You don't have access to this project")
        return project

    async def _require_admin(self, user, workspace):
        exists = await Membership.objects.filter(
            user=user, workspace=workspace,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
            status=MembershipStatus.ACTIVE,
        ).aexists()
        if not exists:
            raise AuthorizationError("Only workspace owners and admins can perform this action")

    def _project_data(self, project):
        return {
            "id": str(project.id), "workspace_id": str(project.workspace_id),
            "workspace_name": project.workspace.name, "name": project.name,
            "description": project.description or "",
        }

    @route.get("/", response={200: dict})
    async def list_projects(self, request):
        projects = []
        async for p in Project.objects.filter(
            workspace__memberships__user=request.auth,
            workspace__memberships__status=MembershipStatus.ACTIVE
        ).select_related("workspace"):
            projects.append(self._project_data(p))
        return CustomResponse.success(message="Projects retrieved successfully!", data=projects)

    @route.post("/", response={201: dict, 400: ErrorResponse, 403: ErrorResponse})
    async def create_project(self, request, data: ProjectCreateSchema):
        membership = await Membership.objects.filter(
            user=request.auth, workspace_id=data.workspace_id, status=MembershipStatus.ACTIVE,
        ).select_related("workspace").afirst()
        if not membership:
            raise AuthorizationError("You don't have access to this workspace")
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only workspace owners and admins can create projects")
        if await Project.objects.filter(workspace=membership.workspace, name=data.name).aexists():
            raise BodyValidationError("name", f"Project '{data.name}' already exists in this workspace")

        project = await Project.objects.acreate(workspace=membership.workspace, name=data.name, description=data.description)
        project.workspace = membership.workspace
        logger.info(f"PROJECT_CREATED: Project '{project.name}' (ID: {project.id}) created in workspace '{project.workspace.name}' by user {request.auth.email}")
        return CustomResponse.success(message="Project Created Successfully!", data=self._project_data(project), status_code=201)

    @route.get("/{project_name}/", response={200: dict, 404: ErrorResponse})
    async def get_project(self, request, project_name: str):
        project = await self._resolve_project(request.auth, project_name)
        return CustomResponse.success(message="Project retrieved successfully", data=self._project_data(project))

    @route.patch("/{project_name}/", response={200: dict, 403: ErrorResponse})
    async def update_project(self, request, project_name: str, data: ProjectUpdateSchema):
        project = await self._resolve_project(request.auth, project_name)
        await self._require_admin(request.auth, project.workspace)
        if data.name is not None and data.name != project.name:
            if await Project.objects.filter(workspace=project.workspace, name=data.name).aexists():
                raise BodyValidationError("name", f"Project '{data.name}' already exists")
            project.name = data.name
        if data.description is not None:
            project.description = data.description
        await project.asave()
        return CustomResponse.success(message="Project updated successfully", data=self._project_data(project))

    @route.delete("/{project_name}/", response={200: SuccessResponse})
    async def delete_project(self, request, project_name: str):
        project = await self._resolve_project(request.auth, project_name)
        await self._require_admin(request.auth, project.workspace)
        name = project.name
        count = await project.secrets.acount()
        await project.adelete()
        logger.warning(f"PROJECT_DELETED: Project '{name}' (Secrets: {count}) deleted by user {request.auth.email}")
        return CustomResponse.success(message=f"Project '{name}' and {count} secrets deleted successfully")

    # --- Workspace-scoped project endpoints ---

    @route.get("/{workspace_id}/{project_name}/", response={200: dict, 404: ErrorResponse})
    async def get_project_ws(self, request, workspace_id: uuid.UUID, project_name: str):
        project = await self._resolve_project(request.auth, project_name, workspace_id)
        return CustomResponse.success(message="Project retrieved successfully", data=self._project_data(project))

    @route.patch("/{workspace_id}/{project_name}/", response={200: dict, 403: ErrorResponse})
    async def update_project_ws(self, request, workspace_id: uuid.UUID, project_name: str, data: ProjectUpdateSchema):
        project = await self._resolve_project(request.auth, project_name, workspace_id)
        await self._require_admin(request.auth, project.workspace)
        if data.name is not None and data.name != project.name:
            if await Project.objects.filter(workspace=project.workspace, name=data.name).aexists():
                raise BodyValidationError("name", f"Project '{data.name}' already exists")
            project.name = data.name
        if data.description is not None:
            project.description = data.description
        await project.asave()
        return CustomResponse.success(message="Project updated successfully", data=self._project_data(project))

    @route.delete("/{workspace_id}/{project_name}/", response={200: SuccessResponse})
    async def delete_project_ws(self, request, workspace_id: uuid.UUID, project_name: str):
        project = await self._resolve_project(request.auth, project_name, workspace_id)
        await self._require_admin(request.auth, project.workspace)
        name = project.name
        count = await project.secrets.acount()
        await project.adelete()
        return CustomResponse.success(message=f"Project '{name}' and {count} secrets deleted successfully")

    # --- Invite ---

    @route.post("/{workspace_id}/{project_name}/invite/", response={201: dict, 400: ErrorResponse, 404: ErrorResponse})
    async def invite(self, request, workspace_id: uuid.UUID, project_name: str, data: ProjectInviteSchema):
        project = await self._resolve_project(request.auth, project_name, workspace_id)
        await self._require_admin(request.auth, project.workspace)
        invitee = await User.objects.filter(email=data.email).afirst()
        if not invitee:
            raise NotFoundError(f"User with email {data.email} not found")

        current_ws = project.workspace
        is_personal = current_ws.type == WorkspaceType.PERSONAL

        if is_personal:
            if not data.encrypted_workspace_key_owner:
                raise BodyValidationError("encrypted_workspace_key_owner", "Required when migrating from personal workspace")
            new_ws = await Workspace.objects.acreate(name=project.name, owner=request.auth, type=WorkspaceType.SHARED)
            await Membership.objects.acreate(user=request.auth, workspace=new_ws, role=MembershipRole.OWNER, status=MembershipStatus.ACTIVE, encrypted_workspace_key=data.encrypted_workspace_key_owner)
            project.workspace = new_ws
            await project.asave()
            for si in data.secrets:
                await Secret.objects.aupdate_or_create(project=project, key=si.key, environment=si.environment, defaults={"value": encryption_service.encrypt(si.value)})
            ws_for_invite = new_ws
        else:
            if await Membership.objects.filter(user=invitee, workspace=current_ws).aexists():
                raise BodyValidationError("email", f"User {data.email} is already a member of this workspace")
            ws_for_invite = current_ws

        inv_m = await Membership.objects.acreate(user=invitee, workspace=ws_for_invite, role=data.role, status=MembershipStatus.ACTIVE, encrypted_workspace_key=data.encrypted_workspace_key_invitee)
        return CustomResponse.success(message=f"Successfully invited {invitee.email} to project '{project.name}'", data={
            "workspace_id": str(ws_for_invite.id), "workspace_name": ws_for_invite.name, "workspace_type": ws_for_invite.type,
            "invitee_email": invitee.email, "invitee_role": inv_m.role, "migrated_from_personal": is_personal,
        }, status_code=201)

    # --- Environment info ---

    @route.get("/{project_id}/environments/", response={200: dict, 404: ErrorResponse})
    async def environments(self, request, project_id: uuid.UUID):
        project = await self._resolve_project_by_id(request.auth, project_id)
        counts = {"development": 0, "staging": 0, "production": 0}
        async for row in Secret.objects.filter(project=project).values("environment").annotate(count=Count("id")):
            if row["environment"] in counts:
                counts[row["environment"]] = row["count"]
        return CustomResponse.success(message="Environment counts retrieved", data={
            "project_id": str(project_id),
            "environments": {env: {"secret_count": c} for env, c in counts.items()},
        })

    @route.get("/{project_id}/secrets/coverage/", response={200: dict, 404: ErrorResponse})
    async def secrets_coverage(self, request, project_id: uuid.UUID):
        project = await self._resolve_project_by_id(request.auth, project_id)
        cov = {}
        async for s in Secret.objects.filter(project=project).only("key", "environment"):
            if s.key not in cov:
                cov[s.key] = {"key_name": s.key, "development": False, "staging": False, "production": False}
            if s.environment in cov[s.key]:
                cov[s.key][s.environment] = True
        return CustomResponse.success(message="Secrets coverage retrieved", data={"project_id": str(project_id), "keys": sorted(cov.values(), key=lambda x: x["key_name"])})

    @route.get("/{project_id}/secrets/diff/", response={200: dict, 400: ErrorResponse})
    async def secrets_diff(self, request, project_id: uuid.UUID):
        project = await self._resolve_project_by_id(request.auth, project_id)
        from_env = request.GET.get("from", "development")
        to_env = request.GET.get("to", "production")
        valid = ["development", "staging", "production"]
        if from_env not in valid or to_env not in valid:
            raise BodyValidationError("environment", "Invalid from/to environment")

        from_keys = set()
        to_keys = set()
        async for s in Secret.objects.filter(project=project, environment__in=[from_env, to_env]).values("key", "environment"):
            if s["environment"] == from_env:
                from_keys.add(s["key"])
            else:
                to_keys.add(s["key"])

        return CustomResponse.success(message="Cross-environment diff retrieved", data={
            "in_from_only": sorted(from_keys - to_keys), "in_to_only": sorted(to_keys - from_keys), "in_both": sorted(from_keys & to_keys),
        })


@api_controller("/secrets", tags=["Secrets"], auth=JWTAuth())
class SecretsController(SecretsMixin):

    async def _resolve(self, user, project_id):
        project = await Project.objects.select_related("workspace").filter(
            id=project_id,
            workspace__memberships__user=user,
            workspace__memberships__status=MembershipStatus.ACTIVE
        ).afirst()
        if not project:
            if await Project.objects.filter(id=project_id).aexists():
                raise AuthorizationError("You don't have access to this project")
            raise NotFoundError("Project not found")
        membership = await Membership.objects.filter(user=user, workspace_id=project.workspace_id, status=MembershipStatus.ACTIVE).afirst()
        return project, membership

    def _validate_env(self, environment):
        if environment not in ["development", "staging", "production"]:
            raise BodyValidationError("environment", f"Invalid environment '{environment}'.")

    @route.post("/", response={201: dict, 403: ErrorResponse, 404: ErrorResponse})
    async def bulk_upsert(self, request, data: SecretBulkUpsertSchema):
        project, membership = await self._resolve(request.auth, data.project_id)
        if membership.role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")

        env = data.environment
        incoming = [k.upper() for k in data.secrets.keys()]
        existing = {}
        async for s in Secret.objects.filter(project=project, environment=env, key__in=incoming):
            existing[s.key] = s

        to_create, to_update = [], []
        for key, value in data.secrets.items():
            k = key.upper()
            enc = encryption_service.encrypt(value)
            if k in existing:
                existing[k].value = enc
                to_update.append(existing[k])
            else:
                to_create.append(Secret(project=project, environment=env, key=k, value=enc, policy={}))

        if to_create:
            await Secret.objects.abulk_create(to_create)
        if to_update:
            await Secret.objects.abulk_update(to_update, ["value"])

        logger.info(f"SECRETS_BULK_UPSERT: Project '{project.name}' ({project.id}) env '{env}' - Created: {len(to_create)}, Updated: {len(to_update)} by user {request.auth.email}")
        return CustomResponse.success(message="Secrets processed", data={
            "created": len(to_create), "updated": len(to_update),
            "total": len(to_create) + len(to_update), "environment": env,
        }, status_code=201)

    @route.post("/bulk/", response={201: dict, 403: ErrorResponse})
    async def bulk_upsert_alias(self, request, data: SecretBulkUpsertSchema):
        return await self.bulk_upsert(request, data)

    @route.get("/{project_id}/", response={200: dict, 404: ErrorResponse})
    async def list_secrets(self, request, project_id: uuid.UUID, environment: str = "development"):
        project, _ = await self._resolve(request.auth, project_id)
        self._validate_env(environment)
        secrets = []
        async for s in Secret.objects.filter(project=project, environment=environment).values("id", "key", "value", "policy"):
            try:
                secrets.append({
                    "id": str(s["id"]),
                    "key": s["key"],
                    "value": encryption_service.decrypt(s["value"]),
                    "policy": s["policy"] or {},
                })
            except Exception:
                continue
        return CustomResponse.success(message="Secrets retrieved successfully", data={"project_id": str(project_id), "secrets": secrets})

    @route.get("/{project_id}/{key}/", response={200: dict, 404: ErrorResponse})
    async def get_secret(self, request, project_id: uuid.UUID, key: str, environment: str = "development"):
        project, _ = await self._resolve(request.auth, project_id)
        self._validate_env(environment)
        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        return CustomResponse.success(message="Secret retrieved successfully", data={
            "id": str(secret.id),
            "key": secret.key,
            "value": encryption_service.decrypt(secret.value),
            "policy": secret.policy or {},
        })

    @route.patch("/{project_id}/{key}/", response={200: dict, 403: ErrorResponse, 404: ErrorResponse})
    async def update_secret(self, request, project_id: uuid.UUID, key: str, data: SecretUpdateSchema, environment: str = "development"):
        project, membership = await self._resolve(request.auth, project_id)
        if membership.role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")
        self._validate_env(environment)
        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        secret.value = encryption_service.encrypt(data.value)
        await secret.asave()
        return CustomResponse.success(message="Secret updated successfully", data={
            "id": str(secret.id),
            "key": secret.key,
            "value": encryption_service.decrypt(secret.value),
            "policy": secret.policy or {},
        })

    @route.delete("/{project_id}/{key}/", response={200: SuccessResponse, 404: ErrorResponse})
    async def delete_secret(self, request, project_id: uuid.UUID, key: str, environment: str = "development"):
        project, membership = await self._resolve(request.auth, project_id)
        if membership.role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")
        self._validate_env(environment)
        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        await secret.adelete()
        logger.warning(f"SECRET_DELETED: Secret '{key.upper()}' deleted from project '{project.name}' ({project.id}) env '{environment}' by user {request.auth.email}")
        return CustomResponse.success(message=f"Secret '{key.upper()}' deleted successfully")

    # --- Environment-scoped (env in URL path) ---

    @route.get("/{project_id}/{environment}/{key}/", response={200: dict, 404: ErrorResponse})
    async def get_secret_env(self, request, project_id: uuid.UUID, environment: str, key: str):
        return await self.get_secret(request, project_id, key, environment)

    @route.patch("/{project_id}/{environment}/{key}/", response={200: dict, 404: ErrorResponse})
    async def update_secret_env(self, request, project_id: uuid.UUID, environment: str, key: str, data: SecretUpdateSchema):
        return await self.update_secret(request, project_id, key, data, environment)

    @route.delete("/{project_id}/{environment}/{key}/", response={200: SuccessResponse, 404: ErrorResponse})
    async def delete_secret_env(self, request, project_id: uuid.UUID, environment: str, key: str):
        return await self.delete_secret(request, project_id, key, environment)

    # --- Policy endpoints ---

    @route.get("/{project_id}/{environment}/{key}/policy/", response={200: dict, 404: ErrorResponse})
    async def get_policy(self, request, project_id: uuid.UUID, environment: str, key: str):
        project, _ = await self._resolve(request.auth, project_id)
        self._validate_env(environment)
        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        return CustomResponse.success(message="Policy retrieved successfully", data=secret.policy or {})

    @route.put("/{project_id}/{environment}/{key}/policy/", response={200: dict, 403: ErrorResponse, 404: ErrorResponse})
    async def set_policy(self, request, project_id: uuid.UUID, environment: str, key: str, data: dict = Body(...)):
        project, membership = await self._resolve(request.auth, project_id)
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only workspace owners and admins can modify policy")
        self._validate_env(environment)
        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        secret.policy = data
        await secret.asave()
        return CustomResponse.success(message="Policy updated successfully", data=secret.policy or {})
