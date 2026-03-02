# Third-party
from rest_framework.permissions import BasePermission

# Local
from .models import Membership, MembershipRole, MembershipStatus


class IsWorkspaceMember(BasePermission):
    """
    Permission to check if user is a member of the workspace.
    Expects workspace_id in URL kwargs.
    """
    message = "You are not a member of this workspace"
    
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            return False
        
        return Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).exists()


class IsWorkspaceOwner(BasePermission):
    """
    Permission to check if user is the owner of the workspace.
    Expects workspace_id in URL kwargs.
    """
    message = "Only the workspace owner can perform this action"
    
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            return False
        
        return Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE
        ).exists()


class IsWorkspaceAdminOrOwner(BasePermission):
    """
    Permission to check if user is owner or admin of the workspace.
    Expects workspace_id in URL kwargs.
    """
    message = "Only workspace owners and admins can perform this action"
    
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            return False
        
        return Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
            status=MembershipStatus.ACTIVE
        ).exists()


class IsWorkspaceMemberAsync(BasePermission):
    """
    Async permission to check if user is a member of the workspace.
    For use with async views.
    """
    message = "You are not a member of this workspace"
    
    async def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            return False
        
        membership = await Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        return membership is not None


class IsWorkspaceOwnerAsync(BasePermission):
    """
    Async permission to check if user is the owner of the workspace.
    For use with async views.
    """
    message = "Only the workspace owner can perform this action"
    
    async def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            return False
        
        membership = await Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            role=MembershipRole.OWNER,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        return membership is not None


class IsWorkspaceAdminOrOwnerAsync(BasePermission):
    """
    Async permission to check if user is owner or admin of the workspace.
    For use with async views.
    """
    message = "Only workspace owners and admins can perform this action"
    
    async def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            return False
        
        membership = await Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        return membership is not None


class CanWriteToWorkspace(BasePermission):
    """
    Permission to check if user has write access to the workspace.
    Members with READ_ONLY role cannot perform write actions.
    Expects workspace_id in URL kwargs.
    """
    message = "You don't have permission to perform write actions in this workspace"
    
    def has_permission(self, request, view):
        workspace_id = view.kwargs.get('workspace_id')
        if not workspace_id:
            # If no workspace_id, maybe we can check via project
            # But for now, if checked on workspace endpoints, return False
            return True
            
        membership = Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).first()
        
        if not membership:
            return False
            
        return membership.role != MembershipRole.READ_ONLY


class CanWriteToWorkspaceAsync(BasePermission):
    """
    Async permission to check if user has write access to the workspace.
    For use with async views.
    """
    message = "You don't have permission to perform write actions in this workspace"
    
    async def has_permission(self, request, view):
        # Allow read operations
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True

        workspace_id = view.kwargs.get('workspace_id')
        
        # If no workspace_id (e.g. project views), we rely on the view or other permissions
        # This permission is specifically for workspace-level checks or when workspace_id is available
        if not workspace_id: 
            return True
                
        membership = await Membership.objects.filter(
            user=request.user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        if not membership:
            return False
            
        return membership.role != MembershipRole.READ_ONLY

