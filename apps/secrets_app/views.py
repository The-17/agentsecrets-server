# Third-party
from adrf.views import APIView
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from rest_framework.permissions import IsAuthenticated

# Local
from apps.accounts.models import User
from apps.common.response import CustomResponse
from apps.common.services.encryption import EncryptionService as encryption_service
from apps.workspaces.mixins import WorkspaceMixin
from apps.workspaces.models import Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus
from .mixins import ProjectsMixin, SecretsMixin
from .models import Project, Secret
from .permissions import (
    IsProjectMember, 
    IsProjectMemberAsync, 
    IsProjectOwnerOrAdminAsync, 
    IsProjectWriteMemberAsync,
    CanAccessSecret
)
from .serializers import (
    ProjectCreateSerializer,
    ProjectListSerializer,
    ProjectDetailSerializer,
    ProjectInviteSerializer,
    SecretsBulkCreateSerializer,
    SecretsListOutputSerializer,
    SecretDetailSerializer,
    SecretOutputSerializer,
)

tags = [["Projects"], ["Secrets"]]

class ProjectsListCreateAPIView(APIView, ProjectsMixin, WorkspaceMixin):
    serializer_class = ProjectListSerializer
    post_serializer = ProjectCreateSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=tags[0],
        summary="List All Projects",
        description="""
        Retrieve all projects belonging to the authenticated user.
        
        What are Projects?
        Projects are containers that group related secrets together.
        For example, you might have separate projects for:
        - `my-web-app` (production secrets)
        - `my-web-app-staging` (staging secrets)
        - `mobile-app` (mobile app secrets)
        
        Response includes:
        - Project ID (UUID)
        - Project name
        - Description
        """,
        responses={
            200: ProjectListSerializer(many=True),
            401: ProjectListSerializer,
        },
        examples=[
            OpenApiExample(
                "Success Response",
                value={
                    "status": "success",
                    "message": "Projects retrieved successfully!",
                    "data": [
                        {
                            "id": "550e8400-e29b-41d4-a716-446655440000",
                            "owner": "123e4567-e89b-12d3-a456-426614174000",
                            "name": "my-web-app",
                            "description": "Production web application",
                        },
                        {
                            "id": "660e8400-e29b-41d4-a716-446655440000",
                            "owner": "123e4567-e89b-12d3-a456-426614174000",
                            "name": "mobile-app",
                            "description": "Mobile application secrets",
                        }
                    ]
                },
                response_only=True
            )
        ]
    )
    async def get(self, request):
        user = request.user
        projects = await self.get_user_projects(user)
        
        serializer = self.serializer_class(projects, many=True)

        return CustomResponse.success(message="Projects retrieved successfully!", data=serializer.data)
    
    @extend_schema(
        tags=["Projects"],
        summary="Create New Project",
        description="""
        Create a new project for organizing your secrets.
        
        What happens when you create a project?
        1. A new container is created for your secrets
        2. You can start adding secrets to this project
        3. Each project name must be unique for your account
        
        Project Name Rules:
        - Minimum 2 characters
        - Maximum 255 characters
        - Only letters, numbers, hyphens (-), and underscores (_)
        - Examples: `my-app`, `production_api`, `staging-web`
        
        Common Project Naming Patterns:
        - By environment: `myapp-prod`, `myapp-staging`, `myapp-dev`
        - By service: `web-backend`, `mobile-api`, `worker-service`
        - By client: `client-acme`, `client-techcorp`
        
        
        """,
        request=ProjectCreateSerializer,
        responses={
            201: ProjectDetailSerializer,
            400: ProjectDetailSerializer,
            401: ProjectDetailSerializer,
        },
        examples=[
            OpenApiExample(
                "Create Project Request",
                value={
                    "name": "my-web-app",
                    "description": "Production web application secrets"
                },
                request_only=True
            ),
            OpenApiExample(
                "Success Response",
                value={
                    "status": "success",
                    "message": "Project created successfully!",
                    "data": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "name": "my-web-app",
                        "description": "Production web application secrets",
                    }
                },
                response_only=True
            ),
            OpenApiExample(
                "Duplicate Project Error",
                value={
                    "status": "error",
                    "message": "Project 'my-web-app' already exists"
                },
                response_only=True,
                status_codes=["400"]
            )
        ]
    )
    async def post(self, request):
        user = request.user
        serializer = self.post_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        workspace_id = serializer.validated_data["workspace_id"]
        
        # Verify user is a member of the workspace
        membership = await self.get_user_membership(user, workspace_id)
        
        if not membership:
            return CustomResponse.error("You don't have access to this workspace", status_code=403)
        
        # Only owner/admin can create projects
        if membership.role not in [MembershipRole.OWNER, MembershipRole.ADMIN]:
            return CustomResponse.error("Only workspace owners and admins can create projects", status_code=403)
        
        # Check if project with same name exists in this workspace
        workspace = await Workspace.objects.aget_or_none(id=workspace_id)
        exists = await self.check_project_exists(workspace=workspace, name=serializer.validated_data["name"])
        if exists:
            return CustomResponse.error(f"Project '{serializer.validated_data['name']}' already exists in this workspace")

        project = await serializer.acreate(serializer.validated_data)
        response_data = serializer.to_representation(project)

        return CustomResponse.success(message="Project Created Successfully!", data=response_data, status_code=201)
    

class ProjectDetailAPIView(APIView, ProjectsMixin):
    """
    Manage a specific project - retrieve, update, or delete.
    """
    serializer_class = ProjectDetailSerializer
    permission_classes = [IsAuthenticated, IsProjectMember, IsProjectOwnerOrAdminAsync]

    @extend_schema(
        tags=["Projects"],
        summary="Get Project Details",
        description="""
        Retrieve details of a specific project including secrets count.
        
        Use this endpoint to:
        - Check if a project exists
        - Get project metadata
        """,
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the workspace (optional - for disambiguation)",
                required=False
            ),
            OpenApiParameter(
                name="project_name",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Name of the project (case-insensitive)"
            )
        ],
        responses={
            200: ProjectDetailSerializer,
            404: ProjectDetailSerializer,
        }
    )
    async def get(self, request, project_name, workspace_id=None):
        """Get project details"""
        project = request.project
        
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
        
        serializer = self.serializer_class(project)
        
        return CustomResponse.success(message="Project retrieved successfully", data=serializer.data)
    
    @extend_schema(
        tags=["Projects"],
        summary="Update Project",
        description="""
        Update project name or description.
        
        What can be updated:
        - Project name (must still be unique)
        - Project description
        
        Note: Updating a project does NOT affect its secrets.
        
        """,
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the workspace (optional - for disambiguation)",
                required=False
            ),
            OpenApiParameter(
                name="project_name",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Name of the project (case-insensitive)"
            )
        ],
        request=ProjectCreateSerializer,
        responses={
            200: ProjectDetailSerializer,
            400: ProjectDetailSerializer,
            404: ProjectDetailSerializer,
        }
    )
    async def patch(self, request, project_name, workspace_id=None):
        project = request.project
        
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
        
        serializer = ProjectCreateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        
        # Check for name conflict if name is being changed
        if 'name' in serializer.validated_data:
            new_name = serializer.validated_data['name']
            if new_name != project.name:
                exists = await self.check_project_exists(
                    workspace=project.workspace,
                    name=new_name
                )
                if exists:
                    return CustomResponse.error(message=f"Project '{new_name}' already exists", status_code=400)
                project.name = new_name
        
        if 'description' in serializer.validated_data:
            project.description = serializer.validated_data['description']
        
        await project.asave()
        
        response_serializer = ProjectDetailSerializer(project)
        
        return CustomResponse.success(message="Project updated successfully", data=response_serializer.data)
    
    @extend_schema(
        tags=["Projects"],
        summary="Delete Project",
        description="""
        Delete a project and ALL its secrets permanently.
        
        WARNING: This action is irreversible!
        
        When you delete a project:
        1. The project is permanently deleted
        2. ALL secrets in the project are permanently deleted
        3. This cannot be undone
        
        Best Practice:
        Always back up important secrets before deleting a project.
        """,
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the workspace (optional - for disambiguation)",
                required=False
            ),
            OpenApiParameter(
                name="project_name",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Name of the project to delete (case-insensitive)"
            )
        ],
    )
    async def delete(self, request, project_name, workspace_id=None):
        """Delete project and all its secrets"""
        project = request.project
        
        if not project:
            return CustomResponse.error(
                message="Project not found",
                status_code=404
            )
        
        project_name_str = project.name
        secrets_count = await project.secrets.acount()
        
        await project.adelete()
        
        return CustomResponse.success(message=f"Project '{project_name_str}' and {secrets_count} secrets deleted successfully")


class ProjectInviteAPIView(APIView, ProjectsMixin, WorkspaceMixin):
    """
    Invite a user to a project.
    
    When the project is in a PERSONAL workspace:
    - Creates a new shared workspace named after the project
    - Moves the project to the new workspace
    - Updates secrets with CLI-provided re-encrypted values
    - Creates memberships for owner and invitee
    
    When the project is already in a SHARED workspace:
    - Just adds the invitee as a new member
    """
    permission_classes = [IsAuthenticated, IsProjectMember, IsProjectOwnerOrAdminAsync]
    serializer_class = ProjectInviteSerializer

    @extend_schema(
        tags=["Projects"],
        summary="Invite User to Project",
        description="""
        Invite a user to access a specific project.
        
        For projects in personal workspace:
        1. CLI generates new workspace key
        2. CLI re-encrypts all secrets with new key
        3. CLI encrypts workspace key for owner + invitee
        4. API creates shared workspace, moves project, updates secrets
        
        For projects already shared:
        1. CLI encrypts existing workspace key for invitee
        2. API adds new member
        
        Only project owners and admins can invite users.
        """,
        parameters=[
            OpenApiParameter(
                name="workspace_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the workspace containing the project"
            ),
            OpenApiParameter(
                name="project_name",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Name of the project to invite to (case-insensitive)"
            )
        ],
        responses={
            201: {"description": "User invited successfully"},
            400: {"description": "Bad request"},
            403: {"description": "Permission denied"},
            404: {"description": "Project or user not found"}
        }
    )
    async def post(self, request, project_name, workspace_id):
        project = request.project
        
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        
        # Find invitee
        invitee = await User.objects.filter(email=data['email']).afirst()
        if not invitee:
            return CustomResponse.error(message=f"User with email {data['email']} not found", status_code=404)
        
        current_workspace = project.workspace
        is_personal = current_workspace.type == WorkspaceType.PERSONAL
        
        if is_personal:
            # Validate required fields for migration
            if not data.get('encrypted_workspace_key_owner'):
                return CustomResponse.error(
                    message="encrypted_workspace_key_owner is required when migrating from personal workspace",
                    status_code=400
                )
            if not data.get('secrets'):
                return CustomResponse.error(
                    message="secrets are required when migrating from personal workspace",
                    status_code=400
                )
            
            # Create new shared workspace
            new_workspace = await Workspace.objects.acreate(
                name=project.name,
                owner=request.user,
                type=WorkspaceType.SHARED
            )
            
            # Create owner membership with new key
            await Membership.objects.acreate(
                user=request.user,
                workspace=new_workspace,
                role=MembershipRole.OWNER,
                status=MembershipStatus.ACTIVE,
                encrypted_workspace_key=data['encrypted_workspace_key_owner']
            )
            
            # Move project to new workspace
            project.workspace = new_workspace
            await project.asave()
            
            # Update secrets with CLI-provided re-encrypted values
            for secret_item in data['secrets']:
                key = secret_item['key']
                value = secret_item['value']
                
                # Apply API encryption layer
                encrypted_value = encryption_service.encrypt(value)
                
                # Update or create secret
                secret, created = await Secret.objects.aupdate_or_create(
                    project=project,
                    key=key,
                    defaults={'value': encrypted_value}
                )
            
            workspace_for_invite = new_workspace
        else:
            # Project is already in a shared workspace
            workspace_for_invite = current_workspace
            
            # Check if invitee is already a member
            existing_membership = await Membership.objects.filter(
                user=invitee,
                workspace=workspace_for_invite
            ).afirst()
            
            if existing_membership:
                return CustomResponse.error(
                    message=f"User {data['email']} is already a member of this workspace",
                    status_code=400
                )
        
        # Create invitee membership
        invitee_membership = await Membership.objects.acreate(
            user=invitee,
            workspace=workspace_for_invite,
            role=data['role'],
            status=MembershipStatus.ACTIVE,
            encrypted_workspace_key=data['encrypted_workspace_key_invitee']
        )
        
        return CustomResponse.success(
            message=f"Successfully invited {invitee.email} to project '{project.name}'",
            data={
                'workspace_id': str(workspace_for_invite.id),
                'workspace_name': workspace_for_invite.name,
                'workspace_type': workspace_for_invite.type,
                'invitee_email': invitee.email,
                'invitee_role': invitee_membership.role,
                'migrated_from_personal': is_personal
            },
            status_code=201
        )


class SecretsCreateAPIView(APIView, SecretsMixin, ProjectsMixin):
    serializer_class = SecretsBulkCreateSerializer
    permission_classes = [IsAuthenticated, IsProjectWriteMemberAsync]

    @extend_schema(
        tags=tags[1],
        summary="Create or Update Secrets (Bulk)",
        description="""
        Create or update multiple secrets at once for a project.
        
        How it works:
        1. CLI encrypts secret values with project key
        2. CLI sends secrets with encrypted values
        3. API Layer encrypts the blob again (Double Encryption)
        4. Secrets are stored in database
        5. If a secret key already exists, it's updated
        
        
        Use Cases:
        - Push entire .env file to cloud: `secretscli push`
        - Sync local secrets to API: `secretscli sync`
        - Update multiple secrets at once
        
        Key Format Rules:
        - Must start with a letter
        - Only uppercase letters, numbers, and underscores
        - Examples: `DATABASE_URL`, `API_KEY`, `STRIPE_SECRET`
        """,
        request=SecretsBulkCreateSerializer,
        responses={
            201: SecretsListOutputSerializer,
            400: SecretsListOutputSerializer,
            404: SecretsListOutputSerializer,
            500: SecretsListOutputSerializer,
        },
        examples=[
            OpenApiExample(
                "Create Request",
                value={
                    "project_id": "550e8400-e29b-41d4-a716-446655440000",
                    "secrets": [
                        {
                            "key": "DATABASE_URL",
                            "value": "postgresql://user:pass@localhost/db"
                        },
                        {
                            "key": "API_KEY",
                            "value": "sk_live_abc123xyz"
                        },
                        {
                            "key": "STRIPE_SECRET",
                            "value": "sk_test_xyz789"
                        }
                    ]
                },
                request_only=True
            ),
            OpenApiExample(
                "Success Response",
                value={
                    "status": "success",
                    "message": "Secrets created successfully",
                    "data": {
                        "project_id": "550e8400-e29b-41d4-a716-446655440000",
                        "secrets": [
                            {
                                "id": "660e8400-e29b-41d4-a716-446655440000",
                                "key": "DATABASE_URL",
                                "value": "postgresql://user:pass@localhost/db",
                                "created_at": "2024-01-15T10:30:00Z",
                                "updated_at": "2024-01-15T10:30:00Z"
                            },
                            {
                                "id": "770e8400-e29b-41d4-a716-446655440000",
                                "key": "API_KEY",
                                "value": "sk_live_abc123xyz",
                                "created_at": "2024-01-15T10:30:00Z",
                                "updated_at": "2024-01-15T10:30:00Z"
                            }
                        ]
                    }
                },
                response_only=True
            )
        ]
    )
    async def post(self, request):
        """Create or update multiple secrets"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        project_id = serializer.validated_data["project_id"]
        project = await self.get_project_by_id(project_id)
        
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
        
        secrets_data = serializer.validated_data["secrets"]
        
        # Get all incoming keys
        incoming_keys = [item["key"] for item in secrets_data]
        
        # Fetch ALL existing secrets for the project to handle environment matching
        existing_secrets = {}
        async for secret in Secret.objects.filter(project=project):
            existing_secrets[(secret.environment, secret.key)] = secret
        
        # Prepare secrets for bulk operations
        to_create = []
        to_update = []
        encrypted_values = {}  # Store encrypted values for response
        
        for secret_item in secrets_data:
            environment = secret_item.get("environment", "development")
            key = secret_item["key"]
            value = secret_item["value"]
            
            # Encrypt the value (API's encryption layer - Double Encryption)
            encrypted_value = encryption_service.encrypt(value)
            encrypted_values[key] = encrypted_value
            
            if (environment, key) in existing_secrets:
                # Update existing secret
                existing_secrets[(environment, key)].value = encrypted_value
                to_update.append(existing_secrets[(environment, key)])
            else:
                # Create new secret object
                to_create.append(Secret(
                    project=project,
                    environment=environment,
                    key=key,
                    value=encrypted_value
                ))
        
        # Bulk create new secrets
        created_secrets = []
        if to_create:
            created_secrets = await Secret.objects.abulk_create(to_create)
        
        # Bulk update existing secrets
        if to_update:
            await Secret.objects.abulk_update(to_update, ['value'])
        
        return CustomResponse.success(
            message=f"Secrets bulk processed",
            data={
                "created": len(created_secrets),
                "updated": len(to_update),
                "total": len(created_secrets) + len(to_update)
            }, status_code=201)

class SecretSingleCreateAPIView(APIView, ProjectsMixin):
    permission_classes = [IsAuthenticated, IsProjectMemberAsync]
    
    async def post(self, request):
        project_id = request.data.get("project_id")
        environment = request.data.get("environment", "development")
        key = request.data.get("key")
        value = request.data.get("encrypted_blob")
        
        if not all([project_id, key, value]):
            return CustomResponse.error(message="project_id, key, and encrypted_blob are required", status_code=400)
            
        if environment not in ['development', 'staging', 'production']:
            return CustomResponse.error(message=f"Invalid environment '{environment}'. Valid environments: development, staging, production.", status_code=400)
            
        project = await self.get_project_by_id(project_id)
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
            
        encrypted_value = encryption_service.encrypt(value)
        
        secret, created = await Secret.objects.aupdate_or_create(
            project=project,
            environment=environment,
            key=key.upper(),
            defaults={'value': encrypted_value}
        )
        
        return CustomResponse.success(
            message="Secret processed successfully",
            data={
                "id": str(secret.id),
                "key": secret.key,
                "environment": secret.environment
            }, status_code=201)



class SecretsListAPIView(APIView, SecretsMixin, ProjectsMixin):
    serializer_class = SecretsListOutputSerializer
    permission_classes = [IsAuthenticated, IsProjectMemberAsync]

    @extend_schema(
        tags=["Secrets"],
        summary="List All Secrets in Project",
        description="""
        Retrieve all secrets for a specific project.
        
        How it works:
        1. CLI requests secrets for a project
        2. API returns encrypted secret blobs (API layer decrypted)
        3. CLI decrypts with user's master key and project key
        4. CLI writes to .env file

        Common Use Cases:
        - Pull secrets to local .env: `secretscli pull`
        - Sync secrets across machines
        - Backup secrets locally
        
        Response Format:
        Returns an array of secrets with their keys and encrypted values.
        The `value` field contains the secret blob encrypted by the CLI.
        """,
        parameters=[
            OpenApiParameter(
                name="project_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the project to list secrets from"
            )
        ],
        responses={
            200: SecretsListOutputSerializer,
            404: SecretsListOutputSerializer,
        },
        examples=[
            OpenApiExample(
                "Success Response",
                value={
                    "status": "success",
                    "message": "Secrets retrieved successfully",
                    "data": {
                        "project_id": "550e8400-e29b-41d4-a716-446655440000",
                        "secrets": [
                            {
                                "id": "660e8400-e29b-41d4-a716-446655440000",
                                "key": "DATABASE_URL",
                                "value": "postgresql://user:pass@localhost/db"
                            },
                            {
                                "id": "770e8400-e29b-41d4-a716-446655440000",
                                "key": "API_KEY",
                                "value": "sk_live_abc123xyz"
                            }
                        ]
                    }
                },
                response_only=True
            )
        ]
    )
    async def get(self, request, project_id):
        """List all secrets in a project"""
        project = request.project
        
        environment = request.query_params.get('environment', 'development')
        if environment not in ['development', 'staging', 'production']:
            return CustomResponse.error(message=f"Invalid environment '{environment}'. Valid environments: development, staging, production.", status_code=400)
            
        secrets = await self.get_project_secrets(project, environment=environment)
        decrypted_secrets = []

        # Decrypt each secret (remove API's encryption layer)
        for secret in secrets:
            try:
                decrypted_value = encryption_service.decrypt(secret.value)
                decrypted_secrets.append({
                    'id': str(secret.id),
                    'key': secret.key,
                    'value': decrypted_value
                })
            except Exception as e:
                # Skip corrupted secrets
                continue

        serializer = self.serializer_class({"project_id": project_id, "secrets": decrypted_secrets})

        return CustomResponse.success(message="Secrets retrieved successfully", data=serializer.data)


        
class SecretDetailAPIView(APIView, SecretsMixin, ProjectsMixin):
    serializer_class = SecretDetailSerializer
    permission_classes = [IsAuthenticated, CanAccessSecret]

    @extend_schema(
        tags=["Secrets"],
        summary="Get Single Secret",
        description="""
        Retrieve a specific secret by its key.
        
        Use this when you need:
        - A single secret value
        - To check if a specific secret exists
        - To verify a secret's current value
        
        Security:
        - API stores values with its own encryption layer
        - Secret is also encrypted with CLI's layer (project key)
        - Server never sees plaintext values (only seeing CLI-encrypted blobs)
        - CLI must decrypt with user's master key / project key

        """,
        parameters=[
            OpenApiParameter(
                name="project_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the project"
            ),
            OpenApiParameter(
                name="key",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Secret key name (e.g., DATABASE_URL)"
            )
        ],
        responses={
            200: SecretOutputSerializer,
            404: SecretOutputSerializer,
        }
    )
    async def get(self, request, project_id, key, environment=None):
        """Get a specific secret"""
        project = request.project
        
        if not project:
            return CustomResponse.error(message="Project not found",status_code=404)
            
        if not environment:
            environment = request.query_params.get('environment', 'development')
        if environment not in ['development', 'staging', 'production']:
            return CustomResponse.error(message=f"Invalid environment '{environment}'. Valid environments: development, staging, production.", status_code=400)
        
        # Normalize key to uppercase
        key = key.upper()
        
        secret = await self.get_secret(project=project, key=key, environment=environment)
        if not secret:
            return CustomResponse.error(message=f"Secret '{key}' does not exist in this project", status_code=404)
        
        # Decrypt secret (remove API's encryption layer)
        try:
            decrypted_value = encryption_service.decrypt(secret.value)
        except Exception as e:
            return CustomResponse.error(message="Failed to decrypt secret", status_code=500)

        serializer = self.serializer_class({'id': secret.id, 'key': secret.key, 'value': decrypted_value})
        
        return CustomResponse.success(
            message="Secret retrieved successfully", data=serializer.data)

    @extend_schema(
        tags=["Secrets"],
        summary="Update Single Secret",
        description="""
        Update the value of a specific secret.
        
        What happens:**
        1. CLI sends new encrypted value
        2. Old value is overwritten with new value
        
        **Use Cases:**
        - Rotate API keys
        - Update database credentials
        - Change secret values
        """,
        parameters=[
            OpenApiParameter(
                name="project_id",
                type=OpenApiTypes.UUID,
                location=OpenApiParameter.PATH,
                description="UUID of the project"
            ),
            OpenApiParameter(
                name="key",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="Secret key to update"
            )
        ],
        request=SecretDetailSerializer,
        responses={
            200: SecretOutputSerializer,
            404: SecretOutputSerializer,
        }
    )
    async def patch(self, request, project_id, key, environment=None):
        """Update a secret"""
        project = request.project
        
        if not project:
            return CustomResponse.error(message="Project not found",status_code=404)
            
        if not environment:
            environment = request.query_params.get('environment', 'development')
        if environment not in ['development', 'staging', 'production']:
            return CustomResponse.error(message=f"Invalid environment '{environment}'. Valid environments: development, staging, production.", status_code=400)
       
        # Normalize key
        key = key.upper()
        
        secret = await self.get_secret(project=project, key=key, environment=environment)
        if not secret:
            return CustomResponse.error(message=f"Secret '{key}' does not exist in this project", status_code=404)
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Encrypt new value
        new_value = serializer.validated_data.get('value')
        if new_value:
            # Encrypt new value (API's encryption layer)
            encrypted_value = encryption_service.encrypt(new_value)
            secret.value = encrypted_value
            await secret.asave()
            
            # Return decrypted value
            decrypted_value = encryption_service.decrypt(secret.value)
            serializer = self.serializer_class({'id': secret.id, 'key': secret.key, 'value': decrypted_value})
        
            return CustomResponse.success(message="Secret updated successfully", data=serializer.data)
        
        return CustomResponse.error(message="No value provided for update", status_code=400)
    
    @extend_schema(
        tags=["Secrets"],
        summary="Delete Single Secret",
        description="""
        Permanently delete a secret.
        
        ⚠️ WARNING: This action cannot be undone!
        
        The secret is permanently removed from the database.
        Make sure you have a backup if needed.
        
        Use Cases:
        - Remove unused secrets
        - Clean up after service decommissioning
        - Delete compromised secrets (after rotation)

            """,
            parameters=[
                OpenApiParameter(
                    name="project_id",
                    type=OpenApiTypes.UUID,
                    location=OpenApiParameter.PATH,
                    description="UUID of the project"
                ),
                OpenApiParameter(
                    name="key",
                    type=OpenApiTypes.STR,
                    location=OpenApiParameter.PATH,
                    description="Secret key to delete"
                )
            ],
    )
    async def delete(self, request, project_id, key, environment=None):
        """Delete a secret"""
        project = request.project
        
        if not project:
            return CustomResponse.error(message="Project not found",status_code=404)
            
        if not environment:
            environment = request.query_params.get('environment', 'development')
        if environment not in ['development', 'staging', 'production']:
            return CustomResponse.error(message=f"Invalid environment '{environment}'. Valid environments: development, staging, production.", status_code=400)
        
       
        # Normalize key
        key = key.upper()
        
        secret = await self.get_secret(project=project, key=key, environment=environment)
        if not secret:
            return CustomResponse.error(message=f"Secret '{key}' does not exist in this project", status_code=404)
        
        await secret.adelete()

        return CustomResponse.success(message=f"Secret '{key}' deleted successfully")

class ProjectEnvironmentsAPIView(APIView, ProjectsMixin):
    permission_classes = [IsAuthenticated, IsProjectMemberAsync]

    @extend_schema(tags=["Environments"], summary="Get Environments Info")
    async def get(self, request, project_id):
        project = request.project
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
            
        from django.db.models import Count
        counts = {"development": 0, "staging": 0, "production": 0}
        
        async for row in Secret.objects.filter(project=project).values('environment').annotate(count=Count('id')):
            env = row['environment']
            if env in counts:
                counts[env] = row['count']
                
        return CustomResponse.success(
            message="Environment counts retrieved",
            data={
                "project_id": str(project_id),
                "environments": {
                    "development": {"secret_count": counts["development"]},
                    "staging": {"secret_count": counts["staging"]},
                    "production": {"secret_count": counts["production"]}
                }
            }
        )

class ProjectSecretsCoverageAPIView(APIView, ProjectsMixin):
    permission_classes = [IsAuthenticated, IsProjectMemberAsync]

    @extend_schema(tags=["Environments"], summary="Get Secrets Coverage")
    async def get(self, request, project_id):
        project = request.project
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
            
        keys_coverage = {}
        async for secret in Secret.objects.filter(project=project).only('key', 'environment'):
            if secret.key not in keys_coverage:
                keys_coverage[secret.key] = {"key_name": secret.key, "development": False, "staging": False, "production": False}
            if secret.environment in keys_coverage[secret.key]:
                keys_coverage[secret.key][secret.environment] = True
                
        sorted_keys = sorted(keys_coverage.values(), key=lambda x: x["key_name"])
        return CustomResponse.success(
            message="Secrets coverage retrieved",
            data={"project_id": str(project_id), "keys": sorted_keys}
        )

class ProjectSecretsDiffAPIView(APIView, ProjectsMixin):
    permission_classes = [IsAuthenticated, IsProjectMemberAsync]

    @extend_schema(tags=["Environments"], summary="Compare Environments")
    async def get(self, request, project_id):
        project = request.project
        if not project:
            return CustomResponse.error(message="Project not found", status_code=404)
            
        from_env = request.query_params.get('from', 'development')
        to_env = request.query_params.get('to', 'production')
        
        valid_envs = ['development', 'staging', 'production']
        if from_env not in valid_envs or to_env not in valid_envs:
            return CustomResponse.error(message="Invalid from/to environment", status_code=400)
            
        from_keys = {s.key async for s in Secret.objects.filter(project=project, environment=from_env).only('key')}
        to_keys = {s.key async for s in Secret.objects.filter(project=project, environment=to_env).only('key')}
        
        return CustomResponse.success(
            message="Cross-environment diff retrieved",
            data={
                "in_from_only": sorted(list(from_keys - to_keys)),
                "in_to_only": sorted(list(to_keys - from_keys)),
                "in_both": sorted(list(from_keys.intersection(to_keys)))
            }
        )



