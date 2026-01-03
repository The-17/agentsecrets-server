# Local
from .models import Project, Secret
from apps.workspaces.models import Membership, MembershipStatus


class ProjectsMixin:
    
    async def __filter__(self, filters):
        """Filter projects using native async ORM"""
        return [item async for item in Project.objects.filter(**filters)]
    
    async def get_project(self, workspace, project_name):
        """Get a project by workspace and name"""
        return await Project.objects.aget_or_none(workspace=workspace, name=project_name)
    
    async def get_project_by_id(self, project_id):
        return await Project.objects.aget_or_none(id=project_id)
    
    async def get_user_workspaces_ids(self, user):
        """Get all workspace IDs the user is a member of"""
        workspace_ids = []
        async for membership in Membership.objects.filter(
            user=user,
            status=MembershipStatus.ACTIVE
        ):
            workspace_ids.append(membership.workspace_id)
        return workspace_ids
    
    async def get_user_projects(self, user):
        """Get all projects in workspaces the user has access to"""
        workspace_ids = await self.get_user_workspaces_ids(user)
        # Use select_related to prefetch workspace 
        return [
            item async for item in Project.objects.filter(
                workspace_id__in=workspace_ids
            ).select_related('workspace')
        ]
    
    async def check_project_exists(self, project_id=None, workspace=None, name=None):
        if name and workspace:
            exists = await self.get_project(workspace, name)
            if exists is not None:
                return True
            return False
        
        if project_id:
            exists = await self.get_project_by_id(project_id)
            if exists is not None:
                return True
            return False
    
    
class SecretsMixin:

    async def __filter__(self, filters):
        """Filter secrets using native async ORM"""
        return [item async for item in Secret.objects.filter(**filters)]

    async def create_secrets(self, secrets, project):
        secrets = [
            Secret(
                key=secret.key,
                value = secret.value,
                project = project
            )
            for secret in secrets
        ]

        created_secrets = await Secret.objects.abulk_create(secrets, batch_size=10, ignore_conflicts=False)
        return created_secrets

    async def get_project_secrets(self, project):
        return await self.__filter__(filters={"project":project})
    
    async def get_secret(self, project, key):
        return await Secret.objects.aget_or_none(project=project, key=key)
    
    async def secret_exists(self, project, key):
        return await self.__filter__({"project":project, "key":key})
    

