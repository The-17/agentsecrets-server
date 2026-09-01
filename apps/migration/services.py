import logging
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from asgiref.sync import sync_to_async
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from apps.accounts.models import User
from apps.common.exceptions import AuthenticationError, NotFoundError, BodyValidationError
from apps.common.services.encryption import EncryptionService
from apps.secrets_app.models import Secret, Project
from apps.workspaces.models import (
    Workspace,
    Membership,
    MembershipRole,
    MembershipStatus,
    WorkspaceAllowlist,
    AgentRegistration,
    AgentToken,
)
from .models import MigrationTokenNonce
from .schemas import (
    MigrationExportBundleSchema,
    UserProfileExportItemSchema,
    WorkspaceExportItemSchema,
    WorkspaceMemberExportItemSchema,
    WorkspaceAllowlistExportItemSchema,
    ProjectExportItemSchema,
    SecretExportItemSchema,
    AgentRegistrationExportItemSchema,
    AgentTokenExportItemSchema,
    MigrationImportResultSchema,
)

logger = logging.getLogger("apps.migration")


class MigrationToken(AccessToken):
    token_type = "migration"
    lifetime = timedelta(minutes=30)


class MigrationService:

    @staticmethod
    @sync_to_async
    def generate_token(*, user: User) -> Dict[str, Any]:
        """Generates an ephemeral 30-minute migration token with a unique jti nonce."""
        token = MigrationToken()
        token["user_id"] = str(user.id)
        token["email"] = user.email
        jti = str(uuid.uuid4())
        token["jti"] = jti

        # Count owned/joined workspaces
        workspace_count = Membership.objects.filter(
            user=user,
            status=MembershipStatus.ACTIVE,
        ).count()

        expires_at = timezone.now() + timedelta(minutes=30)

        return {
            "token": str(token),
            "expires_at": expires_at.isoformat(),
            "user_email": user.email,
            "workspace_count": workspace_count,
        }

    @staticmethod
    @sync_to_async
    def verify_token(raw_token: str) -> Dict[str, Any]:
        """Validates token signature, expiration, and ensures jti is unconsumed."""
        try:
            token = MigrationToken(raw_token)
        except (TokenError, InvalidToken) as e:
            raise AuthenticationError(f"Invalid or expired migration token: {e}")

        if token.get("token_type") != "migration":
            raise AuthenticationError("Token is not a migration token")

        jti = token.get("jti")
        if not jti:
            raise AuthenticationError("Migration token missing jti claim")

        if MigrationTokenNonce.objects.filter(jti=jti).exists():
            raise AuthenticationError("Migration token has already been used")

        user_id = token.get("user_id")
        email = token.get("email")

        return {
            "user_id": user_id,
            "email": email,
            "jti": jti,
        }

    @staticmethod
    @sync_to_async
    def export_bundle(*, user: User) -> Dict[str, Any]:
        """
        Exports all workspaces, projects, environments, secrets, allowlists, and agent tokens
        belonging to the user. Outer Fernet server encryption is stripped from secret values,
        leaving client-side AES-256-GCM ciphertexts untouched.
        """
        # User profile
        user_profile = UserProfileExportItemSchema(
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            password_hash=user.password,
            public_key=user.public_key,
            encrypted_private_key=user.encrypted_private_key,
        )

        # Get active memberships
        memberships = Membership.objects.filter(
            user=user,
            status=MembershipStatus.ACTIVE,
        ).select_related("workspace")

        workspaces_data: List[WorkspaceExportItemSchema] = []

        for m in memberships:
            ws = m.workspace

            # Members
            members_qs = Membership.objects.filter(workspace=ws, status=MembershipStatus.ACTIVE).select_related("user")
            members_list = [
                WorkspaceMemberExportItemSchema(
                    user_email=mem.user.email,
                    role=mem.role,
                    joined_at=mem.created_at.isoformat() if mem.created_at else None,
                )
                for mem in members_qs
            ]

            # Allowlists
            allowlists_qs = WorkspaceAllowlist.objects.filter(workspace=ws).select_related("added_by")
            allowlist_list = [
                WorkspaceAllowlistExportItemSchema(
                    domain=al.domain,
                    added_by_email=al.added_by.email if al.added_by else None,
                    added_at=al.created_at.isoformat() if al.created_at else None,
                )
                for al in allowlists_qs
            ]

            # Projects & Secrets
            projects_qs = Project.objects.filter(workspace=ws)
            projects_list: List[ProjectExportItemSchema] = []

            for proj in projects_qs:
                secrets_qs = Secret.objects.filter(project=proj, revoked_at__isnull=True)
                secrets_list: List[SecretExportItemSchema] = []

                for sec in secrets_qs:
                    # Strip outer Fernet server-side encryption to expose raw client ciphertext
                    client_ciphertext = EncryptionService.decrypt(sec.value)

                    secrets_list.append(
                        SecretExportItemSchema(
                            id=str(sec.id),
                            project_id=str(proj.id),
                            environment=sec.environment,
                            key=sec.key,
                            client_ciphertext=client_ciphertext,
                            policy=sec.policy,
                            created_at=sec.created_at.isoformat() if sec.created_at else None,
                            updated_at=sec.updated_at.isoformat() if sec.updated_at else None,
                        )
                    )

                projects_list.append(
                    ProjectExportItemSchema(
                        id=str(proj.id),
                        name=proj.name,
                        slug=proj.slug,
                        workspace_id=str(ws.id),
                        created_at=proj.created_at.isoformat() if proj.created_at else None,
                        secrets=secrets_list,
                    )
                )

            # Agents & Tokens
            agents_qs = AgentRegistration.objects.filter(workspace=ws)
            agents_list: List[AgentRegistrationExportItemSchema] = []

            for ag in agents_qs:
                tokens_qs = AgentToken.objects.filter(registration=ag)
                tokens_list = [
                    AgentTokenExportItemSchema(
                        id=str(tok.id),
                        registration_id=str(ag.id),
                        token_hash=tok.token_hash,
                        token_prefix=tok.token_prefix,
                        label=tok.label,
                        environment=tok.environment,
                        is_active=tok.is_active,
                        expires_at=tok.expires_at.isoformat() if tok.expires_at else None,
                        created_at=tok.created_at.isoformat() if tok.created_at else None,
                    )
                    for tok in tokens_qs
                ]

                agents_list.append(
                    AgentRegistrationExportItemSchema(
                        id=str(ag.id),
                        workspace_id=str(ws.id),
                        project_id=str(ag.project_id) if ag.project_id else None,
                        name=ag.name,
                        capabilities=ag.capabilities,
                        is_active=ag.is_active,
                        created_at=ag.created_at.isoformat() if ag.created_at else None,
                        tokens=tokens_list,
                    )
                )

            workspaces_data.append(
                WorkspaceExportItemSchema(
                    id=str(ws.id),
                    name=ws.name,
                    slug=ws.slug,
                    owner_email=ws.owner.email,
                    members=members_list,
                    allowlist=allowlist_list,
                    projects=projects_list,
                    agents=agents_list,
                )
            )

        bundle = MigrationExportBundleSchema(
            exported_at=timezone.now().isoformat(),
            user=user_profile,
            workspaces=workspaces_data,
        )

        return bundle.model_dump()

    @staticmethod
    @sync_to_async
    def import_bundle(*, requesting_user: User, bundle_data: Dict[str, Any], token_jti: Optional[str] = None) -> Dict[str, Any]:
        """
        Imports a migration bundle into the target server inside an atomic database transaction.
        Wraps incoming client ciphertexts with the target server's own Fernet ENCRYPTION_KEY.
        Consumes the token_jti nonce to prevent replay.
        """
        bundle = MigrationExportBundleSchema(**bundle_data)
        user_info = bundle.user

        with transaction.atomic():
            # Consume jti token nonce if provided
            if token_jti:
                MigrationTokenNonce.objects.create(
                    jti=token_jti,
                    user_email=user_info.email,
                    expires_at=timezone.now() + timedelta(minutes=30),
                )

            # Ensure account exists or update keys
            user, created = User.objects.get_or_create(
                email=user_info.email,
                defaults={
                    "first_name": user_info.first_name,
                    "last_name": user_info.last_name,
                    "password": user_info.password_hash,
                    "public_key": user_info.public_key,
                    "encrypted_private_key": user_info.encrypted_private_key,
                },
            )
            if not created:
                if user_info.public_key and not user.public_key:
                    user.public_key = user_info.public_key
                if user_info.encrypted_private_key and not user.encrypted_private_key:
                    user.encrypted_private_key = user_info.encrypted_private_key
                user.save(update_fields=["public_key", "encrypted_private_key"])

            workspaces_count = 0
            projects_count = 0
            secrets_count = 0
            agents_count = 0
            allowlist_count = 0

            for ws_item in bundle.workspaces:
                # Find owner
                owner_user, _ = User.objects.get_or_create(
                    email=ws_item.owner_email,
                    defaults={
                        "first_name": ws_item.owner_email.split("@")[0],
                        "last_name": "User",
                    },
                )

                # Upsert Workspace
                workspace, _ = Workspace.objects.get_or_create(
                    id=uuid.UUID(ws_item.id),
                    defaults={
                        "name": ws_item.name,
                        "slug": ws_item.slug,
                        "owner": owner_user,
                    },
                )
                workspaces_count += 1

                # Upsert Members
                for mem_item in ws_item.members:
                    m_user, _ = User.objects.get_or_create(
                        email=mem_item.user_email,
                        defaults={"first_name": mem_item.user_email.split("@")[0]},
                    )
                    Membership.objects.get_or_create(
                        workspace=workspace,
                        user=m_user,
                        defaults={
                            "role": mem_item.role,
                            "status": MembershipStatus.ACTIVE,
                        },
                    )

                # Upsert Allowlists
                for al_item in ws_item.allowlist:
                    added_by_user = None
                    if al_item.added_by_email:
                        added_by_user, _ = User.objects.get_or_create(
                            email=al_item.added_by_email,
                            defaults={"first_name": al_item.added_by_email.split("@")[0]},
                        )
                    _, al_created = WorkspaceAllowlist.objects.get_or_create(
                        workspace=workspace,
                        domain=al_item.domain,
                        defaults={"added_by": added_by_user},
                    )
                    if al_created:
                        allowlist_count += 1

                # Upsert Projects & Secrets
                for proj_item in ws_item.projects:
                    proj_id = uuid.UUID(proj_item.id)
                    project, _ = Project.objects.get_or_create(
                        id=proj_id,
                        defaults={
                            "workspace": workspace,
                            "name": proj_item.name,
                            "slug": proj_item.slug,
                        },
                    )
                    projects_count += 1

                    for sec_item in proj_item.secrets:
                        # Apply target server Fernet outer layer over raw client ciphertext
                        server_encrypted_val = EncryptionService.encrypt(sec_item.client_ciphertext)

                        sec_id = uuid.UUID(sec_item.id)
                        Secret.objects.update_or_create(
                            id=sec_id,
                            defaults={
                                "project": project,
                                "environment": sec_item.environment,
                                "key": sec_item.key,
                                "value": server_encrypted_val,
                                "policy": sec_item.policy,
                            },
                        )
                        secrets_count += 1

                # Upsert Agents & Tokens
                for ag_item in ws_item.agents:
                    ag_id = uuid.UUID(ag_item.id)
                    agent_reg, _ = AgentRegistration.objects.get_or_create(
                        id=ag_id,
                        defaults={
                            "workspace": workspace,
                            "project_id": uuid.UUID(ag_item.project_id) if ag_item.project_id else None,
                            "name": ag_item.name,
                            "capabilities": ag_item.capabilities,
                            "is_active": ag_item.is_active,
                        },
                    )
                    agents_count += 1

                    for tok_item in ag_item.tokens:
                        tok_id = uuid.UUID(tok_item.id)
                        AgentToken.objects.get_or_create(
                            id=tok_id,
                            defaults={
                                "registration": agent_reg,
                                "token_hash": tok_item.token_hash,
                                "token_prefix": tok_item.token_prefix,
                                "label": tok_item.label,
                                "environment": tok_item.environment,
                                "is_active": tok_item.is_active,
                            },
                        )

            return {
                "status": "success",
                "user_email": user_info.email,
                "summary": MigrationImportResultSchema(
                    workspaces_imported=workspaces_count,
                    projects_imported=projects_count,
                    secrets_imported=secrets_count,
                    agents_imported=agents_count,
                    allowlist_entries_imported=allowlist_count,
                ).model_dump(),
            }
