from .models import Project, Secret
from asgiref.sync import sync_to_async


class ProjectsMixin:
    
    async def __filter__(self, filters):
        queryset = await sync_to_async(lambda: list(Project.objects.filter(**filters)),thread_sensitive=True)()
        return queryset
    
    async def get_project(self, owner, project_name):
        return await Project.objects.aget_or_none(owner=owner, name=project_name)
    
    async def get_project_by_id(self, project_id):
        return await Project.objects.aget_or_none(id=project_id)
    
    async def get_user_projects(self, owner):
        return await self.__filter__(filters={"owner":owner})
    
    async def check_project_exists(self, project_id=None, owner=None, name=None):
        if name and owner:
            exists = await self.get_project(owner, name)
            print(exists)

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
        queryset = await sync_to_async(lambda: list(Secret.objects.filter(**filters)),thread_sensitive=True)()
        return queryset

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
    

