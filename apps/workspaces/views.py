# Standard library
import logging

# Third-party
from adrf.views import APIView
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated

# Local
from apps.accounts.models import User
from apps.common.response import CustomResponse
from apps.common.serializers import ErrorResponseSerializer, SuccessResponseSerializer
from .mixins import WorkspaceMixin
from .models import Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus
from .serializers import (
    WorkspaceSerializer,
    WorkspaceCreateSerializer,
    WorkspaceListSerializer,
    WorkspaceUpdateSerializer,
    MembershipSerializer,
    MemberInviteSerializer,
    MemberUpdateSerializer,
    PublicKeySerializer,
)


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
        existing = await Membership.objects.filter(
            user=invitee,
            workspace_id=workspace_id
        ).afirst()
        
        if existing:
            return CustomResponse.error(
                message="User is already a member of this workspace",
                status_code=400
            )
        
        # Create membership
        membership = await Membership.objects.acreate(
            user=invitee,
            workspace_id=workspace_id,
            role=data['role'],
            status=MembershipStatus.ACTIVE,  # Could be INVITED for email confirmation
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
            return CustomResponse.error(
                message="Admins cannot remove other admins",
                status_code=403
            )
        
        if user_membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error(
                message="You don't have permission to remove members",
                status_code=403
            )
        
        removed_email = target_membership.user.email
        await target_membership.adelete()
        
        logger.info(f"User {request.user.id} removed {user_id} from workspace {workspace_id}")
        
        return CustomResponse.success(
            message=f"Member {removed_email} removed from workspace",
            status_code=200
        )
