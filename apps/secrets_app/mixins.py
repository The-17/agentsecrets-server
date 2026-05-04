# Local
from .models import Project, Secret
from apps.workspaces.models import Membership, MembershipStatus


class ProjectsMixin:

    def get_project(self, workspace, project_name):
        """Get a project by workspace and name"""
        if workspace is None:
            return None
        return Project.objects.get_or_none(workspace_id=workspace.id, name=project_name)

    def get_project_by_id(self, project_id):
        return Project.objects.get_or_none(id=project_id)

    def get_user_workspaces_ids(self, user):
        """Get all workspace IDs the user is a member of"""
        return list(
            Membership.objects.filter(
                user=user, status=MembershipStatus.ACTIVE
            ).values_list("workspace_id", flat=True)
        )

    def get_user_projects(self, user):
        """Get all projects in workspaces the user has access to"""
        workspace_ids = self.get_user_workspaces_ids(user)
        return list(
            Project.objects.filter(workspace_id__in=workspace_ids)
            .select_related("workspace")
        )

    def check_project_exists(self, project_id=None, workspace=None, name=None):
        if name and workspace:
            return self.get_project(workspace, name) is not None
        if project_id:
            return self.get_project_by_id(project_id) is not None
        return False


class SecretsMixin:

    def create_secrets(self, secrets, project):
        secret_objects = [
            Secret(key=s.key, value=s.value, project=project)
            for s in secrets
        ]
        return Secret.objects.bulk_create(secret_objects, batch_size=10, ignore_conflicts=False)

    def get_project_secrets(self, project, environment='development'):
        return list(Secret.objects.filter(project=project, environment=environment))

    def get_secret(self, project, key, environment='development'):
        return Secret.objects.get_or_none(project=project, key=key, environment=environment)

    def secret_exists(self, project, key, environment='development'):
        return Secret.objects.filter(project=project, key=key, environment=environment).exists()
