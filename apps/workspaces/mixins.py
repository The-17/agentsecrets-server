# Local
from .models import Membership, MembershipStatus


class WorkspaceMixin:
    """Mixin for workspace-related helper methods"""

    def get_user_membership(self, user, workspace_id):
        """Get the user's active membership in a workspace"""
        return Membership.objects.filter(
            user=user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).select_related('workspace').first()

    def get_memberships(self, user, workspace_id, target_user_id):
        """Get both the requesting user's membership and target user's membership"""
        user_membership = Membership.objects.filter(
            user=user,
            workspace_id=workspace_id,
            status=MembershipStatus.ACTIVE
        ).first()

        target_membership = Membership.objects.filter(
            user_id=target_user_id,
            workspace_id=workspace_id
        ).select_related('user').first()

        return user_membership, target_membership

    def get_user_workspaces(self, user):
        """Get all active workspaces for a user"""
        return list(
            Membership.objects.filter(
                user=user, status=MembershipStatus.ACTIVE
            ).select_related('workspace')
        )
