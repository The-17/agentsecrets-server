# Local
from .models import Project, Secret
from apps.workspaces.models import Membership, MembershipStatus


class ProjectsMixin:

    async def get_project(self, workspace, project_name):
        """Get a project by workspace and name"""
        if workspace is None:
            return None
        return await Project.objects.aget_or_none(workspace_id=workspace.id, name=project_name)

    async def get_project_by_id(self, project_id):
        return await Project.objects.aget_or_none(id=project_id)

    async def get_user_workspaces_ids(self, user):
        """Get all workspace IDs the user is a member of"""
        return [
            m.workspace_id async for m in Membership.objects.filter(
                user=user, status=MembershipStatus.ACTIVE
            )
        ]

    async def get_user_projects(self, user):
        """Get all projects in workspaces the user has access to"""
        workspace_ids = await self.get_user_workspaces_ids(user)
        return [
            p async for p in Project.objects.filter(
                workspace_id__in=workspace_ids
            ).select_related('workspace')
        ]

    async def check_project_exists(self, project_id=None, workspace=None, name=None):
        if name and workspace:
            return await self.get_project(workspace, name) is not None
        if project_id:
            return await self.get_project_by_id(project_id) is not None
        return False


class SecretsMixin:

    async def create_secrets(self, secrets, project):
        secret_objects = [
            Secret(key=s.key, value=s.value, project=project)
            for s in secrets
        ]
        return await Secret.objects.abulk_create(secret_objects, batch_size=10, ignore_conflicts=False)

    async def get_project_secrets(self, project):
        return [s async for s in Secret.objects.filter(project=project)]

    async def get_secret(self, project, key):
        return await Secret.objects.aget_or_none(project=project, key=key)

    async def secret_exists(self, project, key):
        return await Secret.objects.filter(project=project, key=key).aexists()
