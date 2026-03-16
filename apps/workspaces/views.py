# Standard library
import logging
import hmac
import hashlib
import secrets
import base64

# Django
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q
from django.utils import timezone
from django.conf import settings

# Third-party
from adrf.views import APIView
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from asgiref.sync import sync_to_async

# Local
from apps.accounts.models import User
from apps.common.response import CustomResponse
from apps.common.serializers import ErrorResponseSerializer, SuccessResponseSerializer
from .mixins import WorkspaceMixin
from .models import (
    Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus,
    WorkspaceAllowlist, WorkspaceAllowlistLog,
    AgentRegistration, AgentToken, AuditLogEntry, IdentityLevel
)
from .serializers import (
    WorkspaceSerializer,
    WorkspaceCreateSerializer,
    WorkspaceListSerializer,
    WorkspaceUpdateSerializer,
    MemberInviteSerializer,
    MemberUpdateSerializer,
    WorkspaceAllowlistSerializer,
    WorkspaceAllowlistBulkCreateSerializer,
    WorkspaceAllowlistLogSerializer,
    AgentRegistrationSerializer, AgentRegistrationCreateSerializer,
    AgentTokenSerializer, AgentTokenCreateSerializer,
    AuditLogListEntrySerializer, AuditLogDetailEntrySerializer,
    AuditLogSummarySerializer
)
from .permissions import IsWorkspaceAdminOrOwnerAsync


logger = logging.getLogger("apps.workspaces")

tags = ["Workspaces"]


class WorkspaceListCreateAPIView(APIView):
    """
    List user's workspaces or create a new shared workspace.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = WorkspaceListSerializer

    @extend_schema(
        tags=tags,
        summary="List Workspaces",
        description="""List all workspaces the authenticated user is a member of.
        
        Returns workspace details along with the user's role and encrypted workspace key.
        The CLI should decrypt the workspace key using the user's private key.
        """,
        responses={
            200: SuccessResponseSerializer,
            401: ErrorResponseSerializer
        }
    )
    async def get(self, request):
        """List all workspaces for the authenticated user"""
        user = request.user
        
        workspaces_data = []
        memberships = Membership.objects.filter(
            user=user, 
            status=MembershipStatus.ACTIVE
        ).select_related('workspace')
        
        async for membership in memberships:
            workspaces_data.append({
                'id': str(membership.workspace.id),
                'name': membership.workspace.name,
                'type': membership.workspace.type,
                'role': membership.role,
                'encrypted_workspace_key': membership.encrypted_workspace_key,
                'created_at': membership.workspace.created_at.isoformat()
            })
        
        return CustomResponse.success(
            message="Workspaces retrieved successfully",
            data=workspaces_data,
            status_code=200
        )

    @extend_schema(
        tags=tags,
        summary="Create Workspace",
        description="""Create a new shared workspace.
        
        The CLI must:
        1. Generate a random workspace key
        2. Encrypt the workspace key with the user's public key
        3. Send the encrypted_workspace_key in the request
        
        Personal workspaces are auto-created on registration and cannot be created manually.
        """,
        request=WorkspaceCreateSerializer,
        responses={
            201: SuccessResponseSerializer,
            400: ErrorResponseSerializer
        }
    )
    async def post(self, request):
        """Create a new shared workspace"""
        serializer = WorkspaceCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        
        user = request.user
        
        # Create the workspace
        workspace = await Workspace.objects.acreate(
            name=data['name'],
            owner=user,
            type=WorkspaceType.SHARED
        )
        
        # Create owner membership with the encrypted workspace key
        await Membership.objects.acreate(
            user=user,
            workspace=workspace,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key=data['encrypted_workspace_key']
        )
        
        logger.info(f"User {user.id} created workspace {workspace.id}")
        
        return CustomResponse.success(
            message="Workspace created successfully",
            data={
                'id': str(workspace.id),
                'name': workspace.name,
                'type': workspace.type,
                'role': MembershipRole.OWNER
            },
            status_code=201
        )


class WorkspaceDetailAPIView(APIView, WorkspaceMixin):
    """
    Retrieve, update, or delete a workspace.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = WorkspaceSerializer

    @extend_schema(
        tags=tags,
        summary="Get Workspace Details",
        description="Retrieve details of a specific workspace",
        responses={
            200: SuccessResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def get(self, request, workspace_id):
        """Get workspace details"""
        membership = await self.get_user_membership(request.user, workspace_id)
        
        if not membership:
            return CustomResponse.error(
                message="Workspace not found or you don't have access",
                status_code=404
            )
        
        workspace = membership.workspace
        
        return CustomResponse.success(
            message="Workspace retrieved successfully",
            data={
                'id': str(workspace.id),
                'name': workspace.name,
                'type': workspace.type,
                'role': membership.role,
                'encrypted_workspace_key': membership.encrypted_workspace_key,
                'created_at': workspace.created_at.isoformat(),
                'updated_at': workspace.updated_at.isoformat()
            },
            status_code=200
        )

    @extend_schema(
        tags=tags,
        summary="Update Workspace",
        description="Update workspace details. Only owner and admin can update.",
        request=WorkspaceUpdateSerializer,
        responses={
            200: SuccessResponseSerializer,
            403: ErrorResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def patch(self, request, workspace_id):
        """Update workspace details"""
        membership = await self.get_user_membership(request.user, workspace_id)
        
        if not membership:
            return CustomResponse.error(
                message="Workspace not found or you don't have access",
                status_code=404
            )
        
        # Only owner and admin can update
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(
                message="You don't have permission to update this workspace",
                status_code=403
            )
        
        serializer = WorkspaceUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        
        workspace = membership.workspace
        
        if 'name' in data:
            workspace.name = data['name']
        
        await workspace.asave()
        
        logger.info(f"User {request.user.id} updated workspace {workspace_id}")
        
        return CustomResponse.success(
            message="Workspace updated successfully",
            data={
                'id': str(workspace.id),
                'name': workspace.name,
                'type': workspace.type
            },
            status_code=200
        )

    @extend_schema(
        tags=tags,
        summary="Delete Workspace",
        description="""Delete a workspace. Only the owner can delete.
        
        Warning: This will delete all projects and secrets in the workspace!
        Personal workspaces cannot be deleted.
        """,
        responses={
            200: SuccessResponseSerializer,
            403: ErrorResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def delete(self, request, workspace_id):
        """Delete a workspace"""
        membership = await self.get_user_membership(request.user, workspace_id)
        
        if not membership:
            return CustomResponse.error(
                message="Workspace not found or you don't have access",
                status_code=404
            )
        
        workspace = membership.workspace
        
        # Only owner can delete
        if membership.role != MembershipRole.OWNER:
            return CustomResponse.error(
                message="Only the workspace owner can delete it",
                status_code=403
            )
        
        # Cannot delete personal workspace
        if workspace.type == WorkspaceType.PERSONAL:
            return CustomResponse.error(
                message="Personal workspaces cannot be deleted",
                status_code=403
            )
        
        workspace_name = workspace.name
        await workspace.adelete()
        
        logger.info(f"User {request.user.id} deleted workspace {workspace_id}")
        
        return CustomResponse.success(
            message=f"Workspace '{workspace_name}' deleted successfully",
            status_code=200
        )


class WorkspaceMembersAPIView(APIView, WorkspaceMixin):
    """
    List workspace members or invite a new member.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=tags,
        summary="List Members",
        description="List all members of a workspace",
        responses={
            200: SuccessResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def get(self, request, workspace_id):
        """List all members of a workspace"""
        user_membership = await self.get_user_membership(request.user, workspace_id)
        
        if not user_membership:
            return CustomResponse.error(
                message="Workspace not found or you don't have access",
                status_code=404
            )
        
        members_data = []
        memberships = Membership.objects.filter(
            workspace_id=workspace_id
        ).select_related('user')
        
        async for membership in memberships:
            members_data.append({
                'id': str(membership.id),
                'user_id': str(membership.user.id),
                'email': membership.user.email,
                'name': f"{membership.user.first_name} {membership.user.last_name}",
                'role': membership.role,
                'status': membership.status,
                'created_at': membership.created_at.isoformat()
            })
        
        return CustomResponse.success(
            message="Members retrieved successfully",
            data=members_data,
            status_code=200
        )

    @extend_schema(
        tags=tags,
        summary="Invite Member",
        description="""Invite a user to the workspace.
        
        The CLI must:
        1. Fetch the invitee's public key via GET /api/users/{email}/public-key/
        2. Decrypt the workspace key using the inviter's private key
        3. Re-encrypt the workspace key using the invitee's public key
        4. Send the encrypted_workspace_key in this request
        
        Only owner and admin can invite members.
        """,
        request=MemberInviteSerializer,
        responses={
            201: SuccessResponseSerializer,
            400: ErrorResponseSerializer,
            403: ErrorResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def post(self, request, workspace_id):
        """Invite a user to the workspace"""
        user_membership = await self.get_user_membership(request.user, workspace_id)
        
        if not user_membership:
            return CustomResponse.error(
                message="Workspace not found or you don't have access",
                status_code=404
            )
        
        # Only owner and admin can invite
        if user_membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(
                message="You don't have permission to invite members",
                status_code=403
            )
        
        serializer = MemberInviteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        
        # Find the user to invite
        invitee = await User.objects.filter(email=data['email']).afirst()
        if not invitee:
            return CustomResponse.error(
                message=f"User with email {data['email']} not found",
                status_code=404
            )
        
        # Check if user is already a member
        existing = await Membership.objects.filter(user=invitee, workspace_id=workspace_id).afirst()
        
        if existing:
            return CustomResponse.error(message="User is already a member of this workspace", status_code=400)
        
        # Create membership
        membership = await Membership.objects.acreate(
            user=invitee,
            workspace_id=workspace_id,
            role=data['role'],
            status=MembershipStatus.ACTIVE, 
            encrypted_workspace_key=data['encrypted_workspace_key']
        )
        
        logger.info(f"User {request.user.id} invited {invitee.id} to workspace {workspace_id}")
        
        return CustomResponse.success(
            message=f"Successfully invited {invitee.email} to the workspace",
            data={
                'membership_id': str(membership.id),
                'user_email': invitee.email,
                'role': membership.role
            },
            status_code=201
        )


class WorkspaceMemberDetailAPIView(APIView, WorkspaceMixin):
    """
    Update or remove a workspace member.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=tags,
        summary="Update Member Role",
        description="Update a member's role. Only owner can change roles.",
        request=MemberUpdateSerializer,
        responses={
            200: SuccessResponseSerializer,
            403: ErrorResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def patch(self, request, workspace_id, user_id):
        """Update a member's role"""
        user_membership, target_membership = await self.get_memberships(
            request.user, workspace_id, user_id
        )
        
        if not user_membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
        
        if not target_membership:
            return CustomResponse.error(message="Member not found in this workspace", status_code=404)
        
        # Only owner can change roles
        if user_membership.role != MembershipRole.OWNER:
            return CustomResponse.error(message="Only the workspace owner can change member roles", status_code=403)
        
        # Cannot change owner's role
        if target_membership.role == MembershipRole.OWNER:
            return CustomResponse.error(message="Cannot change the owner's role", status_code=403)
        
        serializer = MemberUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        
        target_membership.role = data['role']
        await target_membership.asave()
        
        logger.info(f"User {request.user.id} changed role of {user_id} to {data['role']} in workspace {workspace_id}")
        
        return CustomResponse.success(
            message=f"Member role updated to {data['role']}",
            data={
                'user_id': str(target_membership.user.id),
                'email': target_membership.user.email,
                'role': target_membership.role
            },
            status_code=200
        )

    @extend_schema(
        tags=tags,
        summary="Remove Member",
        description="Remove a member from the workspace. Owner and admin can remove members.",
        responses={
            200: SuccessResponseSerializer,
            403: ErrorResponseSerializer,
            404: ErrorResponseSerializer
        }
    )
    async def delete(self, request, workspace_id, user_id):
        """Remove a member from the workspace"""
        user_membership, target_membership = await self.get_memberships(
            request.user, workspace_id, user_id
        )
        
        if not user_membership:
            return CustomResponse.error(
                message="Workspace not found or you don't have access",
                status_code=404
            )
        
        if not target_membership:
            return CustomResponse.error(
                message="Member not found in this workspace",
                status_code=404
            )
        
        # Cannot remove owner
        if target_membership.role == MembershipRole.OWNER:
            return CustomResponse.error(
                message="Cannot remove the workspace owner",
                status_code=403
            )
        
        # Only owner and admin can remove (admin cannot remove other admins)
        if user_membership.role == MembershipRole.ADMIN and target_membership.role == MembershipRole.ADMIN:
            return CustomResponse.error(message="Admins cannot remove other admins", status_code=403)
        
        if user_membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(message="You don't have permission to remove members", status_code=403)
        
        removed_email = target_membership.user.email
        await target_membership.adelete()
        
        logger.info(f"User {request.user.id} removed {user_id} from workspace {workspace_id}")
        
        return CustomResponse.success(message=f"Member {removed_email} removed from workspace", status_code=200)


class WorkspaceAllowlistAPIView(APIView, WorkspaceMixin):
    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated(), IsWorkspaceAdminOrOwnerAsync()]
        return [IsAuthenticated()]

    @extend_schema(tags=["Workspaces"], summary="List Allowlist")
    async def get(self, request, workspace_id):
        """List all allowed domains for a workspace. Any member can view."""
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or no access", status_code=404)
            
        allowlist = []
        async for entry in WorkspaceAllowlist.objects.filter(workspace_id=workspace_id).select_related('added_by'):
            allowlist.append(entry)
            
        serializer = WorkspaceAllowlistSerializer(allowlist, many=True)
        return CustomResponse.success("Allowlist retrieved", data=serializer.data, status_code=200)

    @extend_schema(tags=["Workspaces"], summary="Bulk Add to Allowlist", request=WorkspaceAllowlistBulkCreateSerializer)
    async def post(self, request, workspace_id):
        """Add one or more domains. Admin only."""
        # Validate workspace exists and user has access
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or no access", status_code=404)

        serializer = WorkspaceAllowlistBulkCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        domains = serializer.validated_data['domains']

        # Find which domains already exist (fetch only domain strings, not full objects)
        existing_domains = set()
        async for d in WorkspaceAllowlist.objects.filter(
            workspace_id=workspace_id, domain__in=domains
        ).values_list('domain', flat=True):
            existing_domains.add(d)

        new_domains = [d for d in domains if d not in existing_domains]

        if not new_domains:
            return CustomResponse.error(message="All provided domains are already in the allowlist.", status_code=400)

        # Batch create allowlist entries and audit logs
        allowlist_objects = [
            WorkspaceAllowlist(workspace_id=workspace_id, domain=d, added_by=request.user)
            for d in new_domains
        ]
        created_entries = await WorkspaceAllowlist.objects.abulk_create(allowlist_objects)

        log_objects = [
            WorkspaceAllowlistLog(workspace_id=workspace_id, domain=d, action='added', performed_by=request.user)
            for d in new_domains
        ]
        await WorkspaceAllowlistLog.objects.abulk_create(log_objects)

        # Serialize directly from created objects (no re-query needed)
        for entry in created_entries:
            entry.added_by = request.user
        
        return CustomResponse.success(
            f"Added {len(new_domains)} domain(s) to allowlist",
            data=WorkspaceAllowlistSerializer(created_entries, many=True).data,
            status_code=201
        )


class WorkspaceAllowlistDetailAPIView(APIView, WorkspaceMixin):
    def get_permissions(self):
        if self.request.method == 'DELETE':
            return [IsAuthenticated(), IsWorkspaceAdminOrOwnerAsync()]
        return [IsAuthenticated()]

    @extend_schema(tags=["Workspaces"], summary="Remove from Allowlist")
    async def delete(self, request, workspace_id, domain):
        """Remove a domain. Admin only."""
        # Validate workspace exists and user has access
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or no access", status_code=404)

        entry = await WorkspaceAllowlist.objects.filter(
            workspace_id=workspace_id,
            domain=domain.lower()
        ).afirst()
        
        if not entry:
            return CustomResponse.error(message=f"{domain} is not in the allowlist.", status_code=404)

        await entry.adelete()

        await WorkspaceAllowlistLog.objects.acreate(
            workspace_id=workspace_id,
            domain=domain.lower(),
            action='removed',
            performed_by=request.user
        )

        return CustomResponse.success("Domain removed from allowlist", status_code=200)


class WorkspaceAllowlistLogAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["Workspaces"], summary="View Allowlist Logs")
    async def get(self, request, workspace_id):
        """View allowlist change history. Any member can view."""
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or no access", status_code=404)

        logs = []
        async for log in WorkspaceAllowlistLog.objects.filter(workspace_id=workspace_id).select_related('performed_by'):
            logs.append(log)
            
        serializer = WorkspaceAllowlistLogSerializer(logs, many=True)
        return CustomResponse.success("Logs retrieved", data=serializer.data, status_code=200)


class WorkspaceMemberRoleAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["Workspaces"], summary="Change Member Role")
    async def post(self, request, workspace_id, user_id):
        """
        Promote or demote a workspace member.
        Action: 'promote' or 'demote'
        Admin only.
        """
        user_membership, target_membership = await self.get_memberships(
            request.user, workspace_id, user_id
        )

        if not user_membership:
            return CustomResponse.error(message="Workspace not found or no access", status_code=404)

        if user_membership.role != MembershipRole.ADMIN and user_membership.role != MembershipRole.OWNER:
            return CustomResponse.error(message="Only admins/owners can change member roles.", status_code=403)

        action = request.data.get('action')
        if action not in ['promote', 'demote']:
            return CustomResponse.error(message="Action must be promote or demote.", status_code=400)

        if not target_membership:
            return CustomResponse.error(message="User is not a member of this workspace.", status_code=404)

        if action == 'demote':
            if target_membership.role == MembershipRole.ADMIN or target_membership.role == MembershipRole.OWNER:
                admin_count = await Membership.objects.filter(
                    workspace_id=workspace_id,
                    role__in=[MembershipRole.ADMIN, MembershipRole.OWNER],
                    status=MembershipStatus.ACTIVE
                ).acount()
                if admin_count <= 1:
                    return CustomResponse.error(
                        message="You are the only admin in this workspace. Promote another member before demoting yourself.",
                        status_code=400
                    )
            target_membership.role = MembershipRole.MEMBER

        elif action == 'promote':
            target_membership.role = MembershipRole.ADMIN

        await target_membership.asave()

        return CustomResponse.success(
            f"User is now a {target_membership.role}",
            data={
                'user_id': str(target_membership.user.id),
                'role': target_membership.role,
            },
            status_code=200
        )


class AgentListCreateAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def get(self, request, workspace_id):
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        agents = []
        async for agent in AgentRegistration.objects.filter(
            workspace_id=workspace_id,
            project__isnull=True
        ).annotate(
            token_count=Count('tokens'),
            active_token_count=Count('tokens', filter=Q(tokens__revoked_at__isnull=True))
        ):
            agents.append(agent)
            
        serializer = AgentRegistrationSerializer(agents, many=True)
        return CustomResponse.success(data=serializer.data, message="Agents retrieved")

    async def post(self, request, workspace_id):
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(message="You don't have permission to create agents", status_code=403)
            
        serializer = AgentRegistrationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        agent = await AgentRegistration.objects.acreate(
            workspace_id=workspace_id,
            name=serializer.validated_data['name'],
            created_by=request.user
        )

        expires_in = serializer.validated_data.get('expires_in_days')
        expires_at = timezone.now() + timezone.timedelta(days=expires_in) if expires_in else None
        
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        token = await AgentToken.objects.acreate(
            registration=agent,
            workspace_id=workspace_id,
            token_hash=token_hash,
            label=serializer.validated_data.get('label'),
            expires_at=expires_at,
            created_by=request.user
        )
        
        agent_data = AgentRegistrationSerializer(agent).data
        agent_data['token_count'] = 1
        agent_data['active_token_count'] = 1
        
        return CustomResponse.success(data={
            'agent': agent_data,
            'token': raw_token,
            'token_id': token.id
        }, status_code=201, message="Agent created")

class ProjectAgentListCreateAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def get(self, request, workspace_id, project_id):
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        agents = []
        async for agent in AgentRegistration.objects.filter(
            workspace_id=workspace_id,
            project_id=project_id
        ).annotate(
            token_count=Count('tokens'),
            active_token_count=Count('tokens', filter=Q(tokens__revoked_at__isnull=True))
        ):
            agents.append(agent)
            
        serializer = AgentRegistrationSerializer(agents, many=True)
        return CustomResponse.success(data=serializer.data, message="Project agents retrieved")

    async def post(self, request, workspace_id, project_id):
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(message="You don't have permission to create agents", status_code=403)
            
        serializer = AgentRegistrationCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        agent = await AgentRegistration.objects.acreate(
            workspace_id=workspace_id,
            project_id=project_id,
            name=serializer.validated_data['name'],
            created_by=request.user
        )

        expires_in = serializer.validated_data.get('expires_in_days')
        expires_at = timezone.now() + timezone.timedelta(days=expires_in) if expires_in else None
        
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        token = await AgentToken.objects.acreate(
            registration=agent,
            workspace_id=workspace_id,
            token_hash=token_hash,
            label=serializer.validated_data.get('label'),
            expires_at=expires_at,
            created_by=request.user
        )
        
        agent_data = AgentRegistrationSerializer(agent).data
        agent_data['token_count'] = 1
        agent_data['active_token_count'] = 1
        
        return CustomResponse.success(data={
            'agent': agent_data,
            'token': raw_token,
            'token_id': token.id
        }, status_code=201, message="Project agent created")

class AgentTokenListCreateAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def get(self, request, registration_id):
        agent = await AgentRegistration.objects.filter(id=registration_id).afirst()
        if not agent:
            return CustomResponse.error(message="Agent not found", status_code=404)
        
        membership = await self.get_user_membership(request.user, agent.workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        tokens = []
        async for token in AgentToken.objects.filter(registration_id=registration_id):
            tokens.append(token)
            
        serializer = AgentTokenSerializer(tokens, many=True)
        return CustomResponse.success(data=serializer.data, message="Agent tokens retrieved")

    async def post(self, request, registration_id):
        agent = await AgentRegistration.objects.filter(id=registration_id).afirst()
        if not agent:
            return CustomResponse.error(message="Agent not found", status_code=404)
            
        membership = await self.get_user_membership(request.user, agent.workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(message="You don't have permission to create tokens", status_code=403)
            
        serializer = AgentTokenCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        expires_in = serializer.validated_data.get('expires_in_days')
        expires_at = timezone.now() + timezone.timedelta(days=expires_in) if expires_in else None
        
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        token = await AgentToken.objects.acreate(
            registration=agent,
            workspace_id=agent.workspace_id,
            token_hash=token_hash,
            label=serializer.validated_data.get('label'),
            expires_at=expires_at,
            created_by=request.user
        )
        
        return CustomResponse.success(data={
            'token': raw_token,
            'token_id': token.id,
            'token_metadata': AgentTokenSerializer(token).data
        }, status_code=201, message="Agent token created")

    async def delete(self, request, registration_id):
        """Bulk delete tokens for an agent registration"""
        agent = await AgentRegistration.objects.filter(id=registration_id).afirst()
        if not agent:
            return CustomResponse.error(message="Agent not found", status_code=404)
            
        membership = await self.get_user_membership(request.user, agent.workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(message="You don't have permission to revoke tokens", status_code=403)
            
        await AgentToken.objects.filter(registration_id=registration_id).adelete()
        return CustomResponse.success(message="All tokens deleted")

class AgentTokenDeleteView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def delete(self, request, registration_id, token_id):
        agent = await AgentRegistration.objects.filter(id=registration_id).afirst()
        if not agent:
            return CustomResponse.error(message="Agent not found", status_code=404)
            
        membership = await self.get_user_membership(request.user, agent.workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(message="You don't have permission to revoke tokens", status_code=403)
            
        token = await AgentToken.objects.filter(id=token_id, registration_id=registration_id).afirst()
        if not token:
            return CustomResponse.error(message="Token not found", status_code=404)
            
        await token.adelete()
        return CustomResponse.success(message="Token deleted")

class AuditLogListAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def get(self, request):
        workspace_id = request.query_params.get('workspace_id')
        if not workspace_id:
            return CustomResponse.error(message="workspace_id is required", status_code=400)
            
        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
        
        logs_qs = AuditLogEntry.objects.filter(workspace_id=workspace_id)
        
        project_id = request.query_params.get('project_id')
        if project_id:
            logs_qs = logs_qs.filter(project_id=project_id)
            
        logs = []
        async for log in logs_qs.order_by('-timestamp')[:100]:
            logs.append(log)
            
        serializer = AuditLogListEntrySerializer(logs, many=True)
        return CustomResponse.success(data=serializer.data, message="Audit logs retrieved")

class AuditLogDetailAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def get(self, request, log_id):
        log = await AuditLogEntry.objects.filter(id=log_id).select_related('workspace').afirst()
        if not log:
            return CustomResponse.error(message="Log not found", status_code=404)
            
        membership = await self.get_user_membership(request.user, log.workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)
            
        serializer = AuditLogDetailEntrySerializer(log)
        return CustomResponse.success(data=serializer.data, message="Audit log detail retrieved")

class AuditLogSummaryAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def get(self, request):
        workspace_id = request.query_params.get('workspace_id')
        if not workspace_id:
            return CustomResponse.error(message="workspace_id is required", status_code=400)

        membership = await self.get_user_membership(request.user, workspace_id)
        if not membership:
            return CustomResponse.error(message="Workspace not found or you don't have access", status_code=404)

        # Build base queryset with optional date range
        qs = AuditLogEntry.objects.filter(workspace_id=workspace_id)

        start = request.query_params.get('start')
        end = request.query_params.get('end')
        if start:
            qs = qs.filter(timestamp__gte=start)
        if end:
            qs = qs.filter(timestamp__lte=end)

        # Totals
        total_requests = await sync_to_async(qs.count)()
        total_errors = await sync_to_async(qs.filter(status_code__gte=400).count)()

        # By agent
        by_agent_qs = qs.exclude(agent_id__isnull=True).exclude(agent_id='').values('agent_id').annotate(
            count=Count('id')
        ).order_by('-count')
        by_agent = []
        async for row in by_agent_qs:
            by_agent.append({'agent_id': row['agent_id'], 'count': row['count']})

        # By domain
        by_domain_qs = qs.values('target_domain').annotate(
            count=Count('id')
        ).order_by('-count')
        by_domain = []
        async for row in by_domain_qs:
            by_domain.append({'domain': row['target_domain'], 'count': row['count']})

        # By credential
        by_credential_qs = qs.values('credential_ref').annotate(
            count=Count('id')
        ).order_by('-count')
        by_credential = []
        async for row in by_credential_qs:
            by_credential.append({'credential_ref': row['credential_ref'], 'count': row['count']})

        # Anonymous call count
        anonymous_count = await sync_to_async(
            qs.filter(identity_level=IdentityLevel.ANONYMOUS).count
        )()

        return CustomResponse.success(data={
            'period': {'start': start or 'all', 'end': end or 'all'},
            'totals': {'requests': total_requests, 'errors': total_errors},
            'by_agent': by_agent,
            'by_credential': by_credential,
            'by_domain': by_domain,
            'anonymous_call_count': anonymous_count,
        }, message="Audit log summary retrieved")

class AuditLogExportAPIView(APIView, WorkspaceMixin):
    permission_classes = [IsAuthenticated]

    async def post(self, request):
        return CustomResponse.success(data={"job_id": "export_123"}, status_code=202, message="Export started")
        
    async def get(self, request):
        return CustomResponse.success(data={"status": "completed", "download_url": "https://example.com/export.csv"}, message="Export status")

class InternalAgentVerifyAPIView(APIView):
    async def post(self, request):
        token_id = request.data.get('token_id')
        raw_token = request.data.get('token')
        
        if not token_id or not raw_token:
            return Response({"error": "token_id and token are required"}, status=status.HTTP_400_BAD_REQUEST)
            
        token = await AgentToken.objects.select_related('registration').filter(id=token_id).afirst()
        if not token:
            return Response({"valid": False, "reason": "Not found"}, status=status.HTTP_404_NOT_FOUND)
            
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        if not hmac.compare_digest(token_hash, token.token_hash):
            return Response({"valid": False, "reason": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
            
        if token.revoked_at:
            return Response({"valid": False, "reason": "Revoked"}, status=status.HTTP_401_UNAUTHORIZED)
            
        if token.expires_at and token.expires_at < timezone.now():
            return Response({"valid": False, "reason": "Expired"}, status=status.HTTP_401_UNAUTHORIZED)
            
        token.last_used_at = timezone.now()
        await token.asave(update_fields=['last_used_at'])
        
        agent = token.registration
        return Response({
            "valid": True,
            "agent_id": agent.id,
            "agent_name": agent.name,
            "workspace_id": str(token.workspace_id)
        })

class InternalAuditLogCreateAPIView(APIView):
    async def post(self, request):
        entries = request.data if isinstance(request.data, list) else [request.data]
        
        created_logs = []
        for entry in entries:
            log_entry = AuditLogEntry(**entry)
            created_logs.append(log_entry)
            
        await AuditLogEntry.objects.abulk_create(created_logs)
            
        return Response(
            {"created_count": len(created_logs), "ids": [log.id for log in created_logs]}, 
            status=status.HTTP_201_CREATED
        )
