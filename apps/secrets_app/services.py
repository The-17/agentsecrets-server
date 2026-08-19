from __future__ import annotations

import logging
import uuid
from typing import Any
from django.db import transaction
from asgiref.sync import sync_to_async

from apps.accounts.models import User
from apps.common.exceptions import (
    NotFoundError,
    AuthorizationError,
    BodyValidationError,
)
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.models import (
    Workspace,
    Membership,
    WorkspaceType,
    MembershipRole,
    MembershipStatus,
)
from .models import Project, Secret
from .schemas import (
    ProjectCreateSchema,
    ProjectUpdateSchema,
    ProjectInviteSchema,
    SecretBulkUpsertSchema,
    SecretUpdateSchema,
)
from .selectors import ProjectSelector, SecretSelector

logger = logging.getLogger("apps.secrets_app")


class ProjectService:
    """
    Domain service layer for Project creation, updates, deletions, and invitations.
    """

    @staticmethod
    async def create_project(*, user: User, data: ProjectCreateSchema) -> dict[str, Any]:
        membership = await Membership.objects.filter(
            user=user, workspace_id=data.workspace_id, status=MembershipStatus.ACTIVE,
        ).select_related("workspace").afirst()
        if not membership:
            raise AuthorizationError("You don't have access to this workspace")
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only workspace owners and admins can create projects")
        if await Project.objects.filter(workspace=membership.workspace, name=data.name).aexists():
            raise BodyValidationError("name", f"Project '{data.name}' already exists in this workspace")

        project = await Project.objects.acreate(
            workspace=membership.workspace,
            name=data.name,
            description=data.description,
        )
        project.workspace = membership.workspace
        logger.info(
            f"PROJECT_CREATED: Project '{project.name}' (ID: {project.id}) "
            f"created in workspace '{project.workspace.name}'"
        )
        return ProjectSelector.project_data(project)

    @staticmethod
    async def update_project(
        *,
        user: User,
        project_name: str,
        data: ProjectUpdateSchema,
        workspace_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        project = await ProjectSelector.resolve_project(
            user=user, project_name=project_name, workspace_id=workspace_id
        )
        await ProjectSelector.require_admin(user=user, workspace=project.workspace)
        if data.name is not None and data.name != project.name:
            if await Project.objects.filter(workspace=project.workspace, name=data.name).aexists():
                raise BodyValidationError("name", f"Project '{data.name}' already exists")
            project.name = data.name
        if data.description is not None:
            project.description = data.description
        await project.asave()
        return ProjectSelector.project_data(project)

    @staticmethod
    async def delete_project(
        *,
        user: User,
        project_name: str,
        workspace_id: uuid.UUID | None = None,
    ) -> tuple[str, int]:
        project = await ProjectSelector.resolve_project(
            user=user, project_name=project_name, workspace_id=workspace_id
        )
        await ProjectSelector.require_admin(user=user, workspace=project.workspace)
        name = project.name
        count = await project.secrets.acount()
        await project.adelete()
        logger.warning(
            f"PROJECT_DELETED: Project '{name}' (Secrets: {count}) deleted"
        )
        return name, count

    @staticmethod
    async def invite_to_project(
        *,
        user: User,
        project_name: str,
        workspace_id: uuid.UUID,
        data: ProjectInviteSchema,
    ) -> dict[str, Any]:
        project = await ProjectSelector.resolve_project(
            user=user, project_name=project_name, workspace_id=workspace_id
        )
        await ProjectSelector.require_admin(user=user, workspace=project.workspace)
        invitee = await User.objects.filter(email=data.email).afirst()
        if not invitee:
            raise NotFoundError(f"User with email {data.email} not found")

        current_ws = project.workspace
        is_personal = current_ws.type == WorkspaceType.PERSONAL

        if is_personal:
            if not data.encrypted_workspace_key_owner:
                raise BodyValidationError(
                    "encrypted_workspace_key_owner",
                    "Required when migrating from personal workspace",
                )

            @sync_to_async
            def _migrate_and_invite():
                with transaction.atomic():
                    new_ws = Workspace.objects.create(
                        name=project.name, owner=user, type=WorkspaceType.SHARED
                    )
                    Membership.objects.create(
                        user=user,
                        workspace=new_ws,
                        role=MembershipRole.OWNER,
                        status=MembershipStatus.ACTIVE,
                        encrypted_workspace_key=data.encrypted_workspace_key_owner,
                    )
                    project.workspace = new_ws
                    project.save(update_fields=["workspace"])

                    for si in data.secrets:
                        Secret.objects.update_or_create(
                            project=project,
                            key=si.key,
                            environment=si.environment,
                            defaults={"value": encryption_service.encrypt(si.value)},
                        )

                    inv_m = Membership.objects.create(
                        user=invitee,
                        workspace=new_ws,
                        role=data.role,
                        status=MembershipStatus.ACTIVE,
                        encrypted_workspace_key=data.encrypted_workspace_key_invitee,
                    )
                    return new_ws, inv_m

            ws_for_invite, inv_m = await _migrate_and_invite()
        else:
            if await Membership.objects.filter(user=invitee, workspace=current_ws).aexists():
                raise BodyValidationError("email", f"User {data.email} is already a member of this workspace")
            ws_for_invite = current_ws
            inv_m = await Membership.objects.acreate(
                user=invitee,
                workspace=ws_for_invite,
                role=data.role,
                status=MembershipStatus.ACTIVE,
                encrypted_workspace_key=data.encrypted_workspace_key_invitee,
            )

        return {
            "workspace_id": str(ws_for_invite.id),
            "workspace_name": ws_for_invite.name,
            "workspace_type": ws_for_invite.type,
            "invitee_email": invitee.email,
            "invitee_role": inv_m.role,
            "migrated_from_personal": is_personal,
        }


class SecretService:
    """
    Domain service layer for Zero-Knowledge secret mutations.
    """

    @staticmethod
    async def bulk_upsert_secrets(
        *,
        user: User,
        project_id: uuid.UUID,
        data: SecretBulkUpsertSchema,
    ) -> dict[str, Any]:
        project, role = await ProjectSelector.resolve_secret_project_and_role(
            user=user, project_id=project_id
        )
        if role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")

        env = data.environment
        incoming = [k.upper() for k in data.secrets.keys()]
        existing: dict[str, Secret] = {}
        async for s in Secret.objects.filter(project=project, environment=env, key__in=incoming):
            existing[s.key] = s

        to_create: list[Secret] = []
        to_update: list[Secret] = []
        for key, value in data.secrets.items():
            k = key.upper()
            enc = encryption_service.encrypt(value)
            if k in existing:
                existing[k].value = enc
                to_update.append(existing[k])
            else:
                to_create.append(Secret(project=project, environment=env, key=k, value=enc, policy={}))

        @sync_to_async
        def _save_secrets():
            with transaction.atomic():
                if to_create:
                    Secret.objects.bulk_create(to_create)
                if to_update:
                    Secret.objects.bulk_update(to_update, ["value"])

        if to_create or to_update:
            await _save_secrets()

        logger.info(
            f"SECRETS_BULK_UPSERT: Project '{project.name}' ({project.id}) env '{env}' - "
            f"Created: {len(to_create)}, Updated: {len(to_update)}"
        )
        return {
            "created": len(to_create),
            "updated": len(to_update),
            "total": len(to_create) + len(to_update),
            "environment": env,
        }

    @staticmethod
    async def update_secret(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        data: SecretUpdateSchema,
        environment: str = "development",
    ) -> dict[str, Any]:
        project, role = await ProjectSelector.resolve_secret_project_and_role(
            user=user, project_id=project_id
        )
        if role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")
        SecretSelector.validate_env(environment)

        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")

        secret.value = encryption_service.encrypt(data.value)
        await secret.asave(update_fields=["value", "updated_at"])

        return {
            "id": str(secret.id),
            "key": secret.key,
            "value": encryption_service.decrypt(secret.value),
            "policy": secret.policy or {},
        }

    @staticmethod
    async def delete_secret(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str = "development",
    ) -> tuple[str, str, uuid.UUID]:
        project, role = await ProjectSelector.resolve_secret_project_and_role(
            user=user, project_id=project_id
        )
        if role == MembershipRole.READ_ONLY:
            raise AuthorizationError("You don't have permission to modify secrets")
        SecretSelector.validate_env(environment)

        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")

        await secret.adelete()
        logger.warning(
            f"SECRET_DELETED: Secret '{key.upper()}' deleted from project "
            f"'{project.name}' ({project.id}) env '{environment}'"
        )
        return key.upper(), project.name, project.id

    @staticmethod
    async def update_secret_policy(
        *,
        user: User,
        project_id: uuid.UUID,
        key: str,
        environment: str,
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        project, role = await ProjectSelector.resolve_secret_project_and_role(
            user=user, project_id=project_id
        )
        if role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            raise AuthorizationError("Only workspace owners and admins can modify policy")
        SecretSelector.validate_env(environment)

        secret = await Secret.objects.filter(project=project, key=key.upper(), environment=environment).afirst()
        if not secret:
            raise NotFoundError(f"Secret '{key.upper()}' does not exist in this project")

        secret.policy = policy
        await secret.asave(update_fields=["policy", "updated_at"])
        return secret.policy or {}
