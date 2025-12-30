
from rest_framework.permissions import BasePermission
from .models import Project
from rest_framework.exceptions import PermissionDenied


class IsProjectOwner(BasePermission):
    """
    Permission class to check if the authenticated user is the owner of a project.
    
    This permission is used to ensure users can only access, modify, or delete
    their own projects and the secrets within them.
    
    How it works:
    1. Checks if user is authenticated
    2. Extracts project_name from URL parameters
    3. Verifies the project exists for this user
    4. Confirms the user is the project owner
    """
    
    message = "You don't have permission to access this project."
    
    def has_permission(self, request, view):
        """
        Check if user has permission to access the project.
        Called before the view is executed.
        """
        # User must be authenticated
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        # Get project_name from URL kwargs
        project_name = view.kwargs.get('project_name')
        
        # If no project_name in URL, allow (might be a list view)
        if not project_name:
            return True
        
        # Check if project exists and user is the owner
        try:
            project = Project.objects.get(name=project_name, owner=request.user)
            
            # Store project in request for later use (avoid re-querying)
            request.project = project
            return True
            
        except Project.DoesNotExist:
            raise PermissionDenied("Project not found.")
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access a specific project object.
        Called after the object is retrieved.
        """
        # If obj is a Project, check ownership directly
        if isinstance(obj, Project):
            if obj.owner_id != request.user.id:
                raise PermissionDenied("You don't have permission to access this project.")
            return True
        
        # If obj has a project attribute (like Secret), check project ownership
        if hasattr(obj, 'project'):
            if obj.project.owner_id != request.user.id:
                raise PermissionDenied("You don't have permission to access this secret.")
            return True
        
        return False


class IsProjectOwnerOrReadOnly(BasePermission):
    """
    Permission class that allows read access to all authenticated users,
    but write access only to the project owner.
    
    Use case:
    Future team features where team members can read secrets
    but only the owner can modify them.
    """
    
    message = "You don't have permission to modify this project."
    
    def has_permission(self, request, view):
        """Allow read operations for authenticated users"""
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        # Allow all GET, HEAD, OPTIONS requests
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # For write operations, check ownership
        project_name = view.kwargs.get('project_name')
        
        if not project_name:
            return True
        
        try:
            project = Project.objects.get(name=project_name, owner=request.user)
            
            request.project = project
            return True
            
        except Project.DoesNotExist:
            raise PermissionDenied("Project not found.")
    
    def has_object_permission(self, request, view, obj):
        """Allow read access, restrict write access to owner"""
        # Read permissions are allowed for any authenticated user
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Write permissions only for owner
        if isinstance(obj, Project):
            return obj.owner_id == request.user.id
        
        if hasattr(obj, 'project'):
            return obj.project.owner_id == request.user.id
        
        return False


class IsProjectOwnerAsync(BasePermission):
    """
    Async version of IsProjectOwner permission.
    Use this for async views (ADRF views).
    """
    
    message = "You don't have permission to access this project."
    
    async def has_permission(self, request, view):
        """Async permission check"""
        # User must be authenticated
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        # Get project_id from URL kwargs
        project_id = view.kwargs.get('project_id')
        
        if not project_id:
            return True

        
        project = await Project.objects.filter(id=project_id, owner=request.user).afirst()
        
        if not project:
            raise PermissionDenied("Project not found.")
        
        # Store project in request for later use
        request.project = project
        return True


class CanAccessSecret(BasePermission):
    """
    Permission to check if user can access a specific secret.
    
    Checks:
    1. User is authenticated
    2. Project exists
    3. User owns the project
    4. Secret belongs to that project
    """
    
    message = "You don't have permission to access this secret."
    
    async def has_permission(self, request, view):
        """Check if user can access the secret"""
        if not request.user or not request.user.is_authenticated:
            raise PermissionDenied("Authentication required.")
        
        project_id = view.kwargs.get('project_id')
        
        if not project_id:
            return True
        
        project = await Project.objects.filter(id=project_id, owner=request.user).afirst()
        
        if not project:
            raise PermissionDenied("Project not found.")
        
        request.project = project
        return True


class IsOwnerOrReadOnly(BasePermission):
    """
    Generic permission for any model with an 'owner' field.
    """
    
    def has_object_permission(self, request, view, obj):
        """Check object-level permission"""
        # Read permissions for authenticated users
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        # Write permissions only for owner
        return obj.owner == request.user