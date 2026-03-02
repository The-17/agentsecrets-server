# Third-party
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

# Local
from .models import Project
from apps.workspaces.models import Membership, MembershipRole, MembershipStatus
from uuid import UUID


class IsProjectMember(BasePermission):
    """
    Permission class to check if the authenticated user is a member of the 
    workspace that contains the project.
    
    This permission is used to ensure users can only access projects
    in workspaces they belong to.
    
    How it works:
    1. Checks if user is authenticated
    2. Extracts project_name from URL parameters
    3. Verifies the project exists
    4. Confirms the user is a member of the project's workspace
    """
    
    message = "You don't have permission to access this project."
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        project_name = view.kwargs.get('project_name')
        workspace_id = view.kwargs.get('workspace_id') 
        
        # Normalize project name to lowercase for case-insensitive matching
        if project_name:
            project_name = project_name.lower()
        else:
            return True
        
        # Get user's workspace IDs
        user_workspace_ids = list(Membership.objects.filter(
            user=request.user,
            status=MembershipStatus.ACTIVE
        ).values_list('workspace_id', flat=True))
        
        try:
            if workspace_id:
                # Normalize workspace_id to UUID (it might already be a UUID object)
                workspace_uuid = workspace_id if isinstance(workspace_id, UUID) else UUID(workspace_id)
                
                # Verify user actually has access to this workspace
                if workspace_uuid not in [wid if isinstance(wid, UUID) else UUID(str(wid)) for wid in user_workspace_ids]:
                    raise PermissionDenied("You don't have access to this workspace.")
                
                # Specific workspace provided in URL - use it directly
                project = Project.objects.select_related('workspace').get(
                    name=project_name,
                    workspace_id=workspace_id
                )
                
            else:
                # No workspace in URL - find in user's workspaces (legacy behavior)
                project = Project.objects.select_related('workspace').get(
                    name=project_name,
                    workspace_id__in=user_workspace_ids
                )
        except Project.DoesNotExist:
            raise PermissionDenied("Project not found.")
        except Project.MultipleObjectsReturned:
            raise PermissionDenied("Ambiguous project name. Please specify workspace.")
        
        request.project = project
        return True


class IsProjectMemberAsync(BasePermission):
    """
    Async version of IsProjectMember permission.
    Use this for async views (ADRF views).
    """
    
    message = "You don't have permission to access this project."
    
    async def has_permission(self, request, view):
        """Async permission check"""
        # User must be authenticated
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        # Support both project_name (for project endpoints) and project_id (for secret endpoints)
        project_name = view.kwargs.get('project_name')
        project_id = view.kwargs.get('project_id')
        workspace_id = view.kwargs.get('workspace_id')
        
        # Normalize project name to lowercase for case-insensitive matching
        if project_name:
            project_name = project_name.lower()
        
        if not project_name and not project_id:
            return True

        if project_id:
            # Direct ID lookup
            project = await Project.objects.select_related('workspace').filter(id=project_id).afirst()
        elif workspace_id:
            # Normalize workspace_id to UUID (it might already be a UUID object)
            workspace_uuid = workspace_id if isinstance(workspace_id, UUID) else UUID(workspace_id)
            
            # Verify user has access to this workspace
            user_workspace_ids = []
            async for membership in Membership.objects.filter(
                user=request.user,
                status=MembershipStatus.ACTIVE
            ):
                user_workspace_ids.append(membership.workspace_id)
            
            if workspace_uuid not in user_workspace_ids:
                raise PermissionDenied("You don't have access to this workspace.")
            
            # Lookup project in the specific workspace
            project = await Project.objects.select_related('workspace').filter(
                name=project_name,
                workspace_id=workspace_uuid
            ).afirst()
        else:
            # Name lookup - scope to user's workspaces (legacy behavior)
            user_workspace_ids = []
            async for membership in Membership.objects.filter(
                user=request.user,
                status=MembershipStatus.ACTIVE
            ):
                user_workspace_ids.append(membership.workspace_id)
            
            project = await Project.objects.select_related('workspace').filter(
                name=project_name,
                workspace_id__in=user_workspace_ids
            ).afirst()
        
        if not project:
            raise PermissionDenied("Project not found.")
        
        # Get membership for the project's workspace
        membership = await Membership.objects.filter(
            user=request.user,
            workspace=project.workspace,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        if not membership:
            raise PermissionDenied("You don't have access to this project.")
        
        # Store project and membership in request for later use
        request.project = project
        request.membership = membership
        return True


class IsProjectOwnerOrAdmin(BasePermission):
    """
    Permission to check if user is owner or admin of the project's workspace.
    Only owners and admins can modify projects.
    """
    
    message = "You don't have permission to modify this project."
    
    def has_permission(self, request, view):
        """Check if user is owner or admin"""
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        # Allow read operations for any member
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        project_name = view.kwargs.get('project_name')
        
        # Normalize project name to lowercase for case-insensitive matching
        if project_name:
            project_name = project_name.lower()
        else:
            return True
        
        try:
            project = Project.objects.select_related('workspace').get(name=project_name)
        except Project.DoesNotExist:
            raise PermissionDenied("Project not found.")
        
        # Check if user is owner or admin of the workspace
        membership = Membership.objects.filter(
            user=request.user,
            workspace=project.workspace,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
            status=MembershipStatus.ACTIVE
        ).first()
        
        if not membership:
            raise PermissionDenied("Only workspace owners and admins can modify projects.")
        
        request.project = project
        return True


class IsProjectOwnerOrAdminAsync(BasePermission):
    """
    Async version of IsProjectOwnerOrAdmin.
    """
    
    message = "You don't have permission to modify this project."
    
    async def has_permission(self, request, view):
        """Async permission check for owner/admin"""
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        # Allow read operations for any member
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Support project_name, project_id, and workspace_id
        project_name = view.kwargs.get('project_name')
        project_id = view.kwargs.get('project_id')
        workspace_id = view.kwargs.get('workspace_id')
        
        # Normalize project name to lowercase for case-insensitive matching
        if project_name:
            project_name = project_name.lower()
        
        if not project_name and not project_id:
            return True
        
        # Get project by ID, workspace+name, or just name
        if project_id:
            project = await Project.objects.select_related('workspace').filter(id=project_id).afirst()
        elif workspace_id:
            # Normalize workspace_id to UUID
            workspace_uuid = workspace_id if isinstance(workspace_id, UUID) else UUID(workspace_id)
            project = await Project.objects.select_related('workspace').filter(
                name=project_name,
                workspace_id=workspace_uuid
            ).afirst()
        else:
            project = await Project.objects.select_related('workspace').filter(name=project_name).afirst()
        
        if not project:
            raise PermissionDenied("Project not found.")
        
        # Check if user is owner or admin
        membership = await Membership.objects.filter(
            user=request.user,
            workspace=project.workspace,
            role__in=[MembershipRole.OWNER, MembershipRole.ADMIN],
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        if not membership:
            raise PermissionDenied("Only workspace owners and admins can modify projects.")
        
        request.project = project
        return True


class CanAccessSecret(BasePermission):
    """
    Permission to check if user can access a specific secret.
    
    Checks:
    1. User is authenticated
    2. Project exists
    3. User is a member of the project's workspace
    """
    
    message = "You don't have permission to access this secret."
    
    async def has_permission(self, request, view):
        """Check if user can access the secret"""
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        project_id = view.kwargs.get('project_id')
        
        if not project_id:
            return True
        
        project = await Project.objects.select_related('workspace').filter(id=project_id).afirst()
        
        if not project:
            raise PermissionDenied("Project not found.")
        
        # Check workspace membership
        membership = await Membership.objects.filter(
            user=request.user,
            workspace=project.workspace,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        if not membership:
            raise PermissionDenied("You don't have access to this project.")
        
        request.project = project
        request.membership = membership
        return True


class IsProjectWriteMemberAsync(BasePermission):
    """
    Async permission to check if user has write access to the project's workspace.
    """
    message = "You don't have permission to modify secrets in this project."
    
    async def has_permission(self, request, view):
        # Allow read operations
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True

        project_id = view.kwargs.get('project_id')
        if not project_id:
            return True
            
        project = await Project.objects.select_related('workspace').filter(id=project_id).afirst()
        if not project:
            return False
            
        membership = await Membership.objects.filter(
            user=request.user,
            workspace=project.workspace,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        if not membership:
            return False
            
        # Store membership for view use
        request.membership = membership
        return membership.role != MembershipRole.READ_ONLY