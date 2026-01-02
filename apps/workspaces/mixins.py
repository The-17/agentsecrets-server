# Local
from .models import Membership, MembershipStatus


class WorkspaceMixin:
    """Mixin for workspace-related helper methods"""
    
    async def get_user_membership(self, user, workspace_id):
        """Get the user's active membership in a workspace"""
        return await Membership.objects.filter(
            user=user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).select_related('workspace').afirst()
    
    async def get_memberships(self, user, workspace_id, target_user_id):
        """Get both the requesting user's membership and target user's membership"""
        user_membership = await Membership.objects.filter(
            user=user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).afirst()
        
        target_membership = await Membership.objects.filter(
            user_id=target_user_id,
            workspace_id=workspace_id
        ).select_related('user').afirst()
        
        return user_membership, target_membership
    
    async def get_user_workspaces(self, user):
        """Get all active workspaces for a user"""
        memberships = []
        async for membership in Membership.objects.filter(
            user=user,
            status=MembershipStatus.ACTIVE
        ).select_related('workspace'):
            memberships.append(membership)
        return memberships
