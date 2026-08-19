from __future__ import annotations

import uuid
from typing import Any
from django.db.models import Count, F

from apps.accounts.models import User
from apps.common.exceptions import NotFoundError, AuthorizationError, BodyValidationError
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.models import Membership, MembershipRole, MembershipStatus
from .models import Project, Secret


class ProjectSelector:
    """
    Pure read-only query selector layer for Projects and Environments.
    """

    @staticmethod
    def project_data(project: Project) -> dict[str, Any]:
        return {
            "id": str(project.id),
            "workspace_id": str(project.workspace_id),
            "workspace_name": project.workspace.name,
            "name": project.name,
            "description": project.description or "",
        }

    @staticmethod
    async def resolve_project(
        *,
        user: User,
        project_name: str,
        workspace_id: uuid.UUID | None = None,
    ) -> Project:
        name = project_name.lower()
        if workspace_id:
            project = await Project.objects.select_related("workspace").filter(
                name=name,
                workspace_id=workspace_id,
                workspace__memberships__user=user,
                workspace__memberships__status=MembershipStatus.ACTIVE,
            ).afirst()
            if not project:
                if await Project.objects.filter(name=name, workspace_id=workspace_id).aexists():
                    raise AuthorizationError("You don't have access to this workspace")
                raise NotFoundError("Project not found")
        else:
            project = await Project.objects.select_related("workspace").filter(
                name=name,
                workspace__memberships__user=user,
                workspace__memberships__status=MembershipStatus.ACTIVE,
            ).afirst()
            if not project:
                raise NotFoundError("Project not found")
        return project

    @staticmethod
    async def resolve_project_by_id(*, user: User, project_id: uuid.UUID) -> Project:
        project = await Project.objects.select_related("workspace").filter(id=project_id).afirst()
        if not project:
            raise NotFoundError("Project not found")
        exists = await Membership.objects.filter(
            user=user, workspace=project.workspace, status=MembershipStatus.ACTIVE
        ).aexists()
        if not exists:
            raise AuthorizationError("You don't have access to this project")
        return project

    @staticmethod
    async def resolve_secret_project_and_role(*, user: User, project_id: uuid.UUID) -> tuple[Project, str]:
        project = await Project.objects.select_related("workspace").filter(
            id=project_id,
            workspace__memberships__user=user,
            workspace__memberships__status=MembershipStatus.ACTIVE,
        ).annotate(
            membership_role=F("workspace__memberships__role")
        ).afirst()
        if not project:
            if await Project.objects.filter(id=project_id).aexists():
                raise AuthorizationError("You don't have access to this project")
            raise NotFoundError("Project not found")
        return project, project.membership_role

    @staticmethod
    async def require_admin(*, user: User, workspace: Any) -> None:
        exists = await Membership.objects.filter(
            user=user,
            workspace=workspace,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
            status=MembershipStatus.ACTIVE,
        ).aexists()
        if not exists:
            raise AuthorizationError("Only workspace owners and admins can perform this action")

    @staticmethod
    async def list_user_projects(*, user: User) -> list[dict[str, Any]]:
        projects: list[dict[str, Any]] = []
        async for p in Project.objects.filter(
            workspace__memberships__user=user,
            workspace__memberships__status=MembershipStatus.ACTIVE,
        ).select_related("workspace"):
            projects.append(ProjectSelector.project_data(p))
        return projects

    @staticmethod
    async def get_environment_counts(*, project: Project) -> dict[str, Any]:
        counts = {"development": 0, "staging": 0, "production": 0}
        async for row in Secret.objects.filter(project=project).values("environment").annotate(count=Count("id")):
            if row["environment"] in counts:
                counts[row["environment"]] = row["count"]
        return {
            "project_id": str(project.id),
            "environments": {env: {"secret_count": c} for env, c in counts.items()},
        }

    @staticmethod
    async def get_secrets_coverage(*, project: Project) -> list[dict[str, Any]]:
        cov: dict[str, dict[str, Any]] = {}
        async for s in Secret.objects.filter(project=project).only("key", "environment"):
            if s.key not in cov:
                cov[s.key] = {"key_name": s.key, "development": False, "staging": False, "production": False}
            if s.environment in cov[s.key]:
                cov[s.key][s.environment] = True
        return sorted(cov.values(), key=lambda x: x["key_name"])

    @staticmethod
    async def get_secrets_diff(*, project: Project, from_env: str, to_env: str) -> dict[str, Any]:
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

        return {
            "in_from_only": sorted(from_keys - to_keys),
            "in_to_only": sorted(to_keys - from_keys),
            "in_both": sorted(from_keys & to_keys),
        }


class SecretSelector:
    """
    Pure read-only query selector layer for Zero-Knowledge Secrets.
    """

    @staticmethod
    def validate_env(environment: str) -> None:
        if environment not in ["development", "staging", "production"]:
            raise BodyValidationError("environment", f"Invalid environment '{environment}'.")

    @staticmethod
    async def list_project_secrets(*, project: Project, environment: str) -> list[dict[str, Any]]:
        SecretSelector.validate_env(environment)
        secrets: list[dict[str, Any]] = []
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
        return secrets

    @staticmethod
    def decrypt_secret_record(secret: Secret) -> dict[str, Any]:
        return {
            "id": str(secret.id),
            "key": secret.key,
            "value": encryption_service.decrypt(secret.value),
            "policy": secret.policy or {},
        }

    @staticmethod
    async def get_secret_by_key(*, project: Project, key: str, environment: str) -> Secret:
        SecretSelector.validate_env(environment)
        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")
        return secret
