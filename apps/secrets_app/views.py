import logging
import uuid
from typing import Any, List, Dict
from ninja_extra import api_controller, route
from ninja import Body

from apps.common.auth import JWTAuth
from apps.common.response import CustomResponse
from apps.common.schemas import SuccessResponse, ErrorResponse, DataResponse
from .schemas import (
    ProjectCreateSchema,
    ProjectUpdateSchema,
    ProjectInviteSchema,
    SecretBulkUpsertSchema,
    SecretUpdateSchema,
    ProjectResponseDataSchema,
    ProjectInviteResponseDataSchema,
    ProjectEnvironmentsResponseDataSchema,
    ProjectSecretsCoverageResponseDataSchema,
    SecretsDiffResponseDataSchema,
    SecretBulkUpsertResponseDataSchema,
    SecretRecordSchema,
    SecretListResponseDataSchema,
)
from .selectors import ProjectSelector, SecretSelector
from .services import ProjectService, SecretService

logger = logging.getLogger("apps.secrets_app")


@api_controller("/projects", tags=["Projects"], auth=JWTAuth())
class ProjectController:
    """
    Project management controllers for workspace-scoped secrets isolation.
    """

    @route.get("/", response={200: DataResponse[List[ProjectResponseDataSchema]]})
    async def list_projects(self, request):
        projects = await ProjectSelector.list_user_projects(user=request.auth)
        return CustomResponse.success(message="Projects retrieved successfully!", data=projects)

    @route.post("/", response={201: DataResponse[ProjectResponseDataSchema], 400: ErrorResponse, 403: ErrorResponse})
    async def create_project(self, request, data: ProjectCreateSchema):
        project_data = await ProjectService.create_project(user=request.auth, data=data)
        return CustomResponse.success(
            message="Project Created Successfully!",
            data=project_data,
            status_code=201,
        )

    @route.get("/{project_name}/", response={200: DataResponse[ProjectResponseDataSchema], 404: ErrorResponse})
    async def get_project(self, request, project_name: str):
        project = await ProjectSelector.resolve_project(user=request.auth, project_name=project_name)
        return CustomResponse.success(
            message="Project retrieved successfully",
            data=ProjectSelector.project_data(project),
        )

    @route.patch("/{project_name}/", response={200: DataResponse[ProjectResponseDataSchema], 403: ErrorResponse})
    async def update_project(self, request, project_name: str, data: ProjectUpdateSchema):
        project_data = await ProjectService.update_project(
            user=request.auth, project_name=project_name, data=data
        )
        return CustomResponse.success(message="Project updated successfully", data=project_data)

    @route.delete("/{project_name}/", response={200: SuccessResponse})
    async def delete_project(self, request, project_name: str):
        name, count = await ProjectService.delete_project(user=request.auth, project_name=project_name)
        return CustomResponse.success(message=f"Project '{name}' and {count} secrets deleted successfully")

    # --- Workspace-scoped project endpoints ---

    @route.get("/{workspace_id}/{project_name}/", response={200: DataResponse[ProjectResponseDataSchema], 404: ErrorResponse})
    async def get_project_ws(self, request, workspace_id: uuid.UUID, project_name: str):
        project = await ProjectSelector.resolve_project(
            user=request.auth, project_name=project_name, workspace_id=workspace_id
        )
        return CustomResponse.success(
            message="Project retrieved successfully",
            data=ProjectSelector.project_data(project),
        )

    @route.patch("/{workspace_id}/{project_name}/", response={200: DataResponse[ProjectResponseDataSchema], 403: ErrorResponse})
    async def update_project_ws(self, request, workspace_id: uuid.UUID, project_name: str, data: ProjectUpdateSchema):
        project_data = await ProjectService.update_project(
            user=request.auth, project_name=project_name, data=data, workspace_id=workspace_id
        )
        return CustomResponse.success(message="Project updated successfully", data=project_data)

    @route.delete("/{workspace_id}/{project_name}/", response={200: SuccessResponse})
    async def delete_project_ws(self, request, workspace_id: uuid.UUID, project_name: str):
        name, count = await ProjectService.delete_project(
            user=request.auth, project_name=project_name, workspace_id=workspace_id
        )
        return CustomResponse.success(message=f"Project '{name}' and {count} secrets deleted successfully")

    # --- Invite ---

    @route.post("/{workspace_id}/{project_name}/invite/", response={201: DataResponse[ProjectInviteResponseDataSchema], 400: ErrorResponse, 404: ErrorResponse})
    async def invite(self, request, workspace_id: uuid.UUID, project_name: str, data: ProjectInviteSchema):
        result = await ProjectService.invite_to_project(
            user=request.auth, project_name=project_name, workspace_id=workspace_id, data=data
        )
        return CustomResponse.success(
            message=f"Successfully invited {result['invitee_email']} to project '{project_name}'",
            data=result,
            status_code=201,
        )

    # --- Environment info ---

    @route.get("/{project_id}/environments/", response={200: DataResponse[ProjectEnvironmentsResponseDataSchema], 404: ErrorResponse})
    async def environments(self, request, project_id: uuid.UUID):
        project = await ProjectSelector.resolve_project_by_id(user=request.auth, project_id=project_id)
        result = await ProjectSelector.get_environment_counts(project=project)
        return CustomResponse.success(message="Environment counts retrieved", data=result)

    @route.get("/{project_id}/secrets/coverage/", response={200: DataResponse[ProjectSecretsCoverageResponseDataSchema], 404: ErrorResponse})
    async def secrets_coverage(self, request, project_id: uuid.UUID):
        project = await ProjectSelector.resolve_project_by_id(user=request.auth, project_id=project_id)
        keys = await ProjectSelector.get_secrets_coverage(project=project)
        return CustomResponse.success(
            message="Secrets coverage retrieved",
            data={"project_id": str(project_id), "keys": keys},
        )

    @route.get("/{project_id}/secrets/diff/", response={200: DataResponse[SecretsDiffResponseDataSchema], 400: ErrorResponse})
    async def secrets_diff(self, request, project_id: uuid.UUID):
        project = await ProjectSelector.resolve_project_by_id(user=request.auth, project_id=project_id)
        from_env = request.GET.get("from", "development")
        to_env = request.GET.get("to", "production")
        result = await ProjectSelector.get_secrets_diff(project=project, from_env=from_env, to_env=to_env)
        return CustomResponse.success(message="Cross-environment diff retrieved", data=result)


@api_controller("/secrets", tags=["Secrets"], auth=JWTAuth())
class SecretsController:
    """
    Zero-Knowledge Secrets CRUD and bulk ingestion controllers.
    """

    @route.post("/", response={201: DataResponse[SecretBulkUpsertResponseDataSchema], 403: ErrorResponse, 404: ErrorResponse})
    async def bulk_upsert(self, request, data: SecretBulkUpsertSchema):
        result = await SecretService.bulk_upsert_secrets(
            user=request.auth, project_id=data.project_id, data=data
        )
        return CustomResponse.success(message="Secrets processed", data=result, status_code=201)

    @route.post("/bulk/", response={201: DataResponse[SecretBulkUpsertResponseDataSchema], 403: ErrorResponse})
    async def bulk_upsert_alias(self, request, data: SecretBulkUpsertSchema):
        return await self.bulk_upsert(request, data)

    @route.get("/{project_id}/", response={200: DataResponse[SecretListResponseDataSchema], 404: ErrorResponse})
    async def list_secrets(self, request, project_id: uuid.UUID, environment: str = "development"):
        project = await ProjectSelector.resolve_project_by_id(user=request.auth, project_id=project_id)
        secrets = await SecretSelector.list_project_secrets(project=project, environment=environment)
        return CustomResponse.success(
            message="Secrets retrieved successfully",
            data={"project_id": str(project_id), "secrets": secrets},
        )

    @route.get("/{project_id}/{key}/", response={200: DataResponse[SecretRecordSchema], 404: ErrorResponse})
    async def get_secret(self, request, project_id: uuid.UUID, key: str, environment: str = "development"):
        project = await ProjectSelector.resolve_project_by_id(user=request.auth, project_id=project_id)
        secret = await SecretSelector.get_secret_by_key(project=project, key=key, environment=environment)
        return CustomResponse.success(
            message="Secret retrieved successfully",
            data=SecretSelector.decrypt_secret_record(secret),
        )

    @route.patch("/{project_id}/{key}/", response={200: DataResponse[SecretRecordSchema], 403: ErrorResponse, 404: ErrorResponse})
    async def update_secret(self, request, project_id: uuid.UUID, key: str, data: SecretUpdateSchema, environment: str = "development"):
        result = await SecretService.update_secret(
            user=request.auth, project_id=project_id, key=key, data=data, environment=environment
        )
        return CustomResponse.success(message="Secret updated successfully", data=result)

    @route.delete("/{project_id}/{key}/", response={200: SuccessResponse, 404: ErrorResponse})
    async def delete_secret(self, request, project_id: uuid.UUID, key: str, environment: str = "development"):
        k, _, _ = await SecretService.delete_secret(
            user=request.auth, project_id=project_id, key=key, environment=environment
        )
        return CustomResponse.success(message=f"Secret '{k}' deleted successfully")

    # --- Environment-scoped (env in URL path) ---

    @route.get("/{project_id}/{environment}/{key}/", response={200: DataResponse[SecretRecordSchema], 404: ErrorResponse})
    async def get_secret_env(self, request, project_id: uuid.UUID, environment: str, key: str):
        return await self.get_secret(request, project_id, key, environment)

    @route.patch("/{project_id}/{environment}/{key}/", response={200: DataResponse[SecretRecordSchema], 404: ErrorResponse})
    async def update_secret_env(self, request, project_id: uuid.UUID, environment: str, key: str, data: SecretUpdateSchema):
        return await self.update_secret(request, project_id, key, data, environment)

    @route.delete("/{project_id}/{environment}/{key}/", response={200: SuccessResponse, 404: ErrorResponse})
    async def delete_secret_env(self, request, project_id: uuid.UUID, environment: str, key: str):
        return await self.delete_secret(request, project_id, key, environment)

    # --- Policy endpoints ---

    @route.get("/{project_id}/{environment}/{key}/policy/", response={200: DataResponse[Dict[str, Any]], 404: ErrorResponse})
    async def get_policy(self, request, project_id: uuid.UUID, environment: str, key: str):
        project = await ProjectSelector.resolve_project_by_id(user=request.auth, project_id=project_id)
        secret = await SecretSelector.get_secret_by_key(project=project, key=key, environment=environment)
        return CustomResponse.success(message="Policy retrieved successfully", data=secret.policy or {})

    @route.put("/{project_id}/{environment}/{key}/policy/", response={200: DataResponse[Dict[str, Any]], 403: ErrorResponse, 404: ErrorResponse})
    async def set_policy(self, request, project_id: uuid.UUID, environment: str, key: str, data: dict = Body(...)):
        policy = await SecretService.update_secret_policy(
            user=request.auth, project_id=project_id, key=key, environment=environment, policy=data
        )
        return CustomResponse.success(message="Policy updated successfully", data=policy)
