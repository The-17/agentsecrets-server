# Standard library
import re

# Third-party
from rest_framework import serializers

# Local
from .models import Project


class ProjectCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=1024, required=False, allow_blank=True)
    workspace_id = serializers.UUIDField(
        help_text="ID of the workspace to create the project in"
    )

    def validate_name(self, value):
        """
        Validate project name format.
        
        Rules:
        - Minimum 2 characters
        - Maximum 255 characters
        - Only letters, numbers, hyphens, and underscores
        - Normalized to lowercase for case-insensitive uniqueness
        """
        value = value.strip().lower()
        
        if len(value) < 2:
            raise serializers.ValidationError("Project name must be at least 2 characters")

        if not re.match(r'^[a-z0-9_-]+$', value):
            raise serializers.ValidationError("Project name can only contain letters, numbers, hyphens, and underscores")
        
        return value
    
    async def acreate(self, validated_data):
        workspace_id = validated_data.pop('workspace_id')
        project = await Project.objects.acreate(workspace_id=workspace_id, **validated_data)
        return project
    
    def to_representation(self, instance):
        return {
            'id': str(instance.id),
            'name': instance.name,
            'description': instance.description,
            'workspace_id': str(instance.workspace_id),
        }


class ProjectListSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    workspace_id = serializers.UUIDField(source="workspace.id", read_only=True)
    workspace_name = serializers.CharField(source="workspace.name", read_only=True)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=1024, allow_blank=True)
    

class ProjectDetailSerializer(ProjectListSerializer):
    pass



class SecretItemSerializer(serializers.Serializer):
    environment = serializers.ChoiceField(choices=['development', 'staging', 'production'], default='development')
    key = serializers.CharField(max_length=255)
    value = serializers.CharField()
    
    def validate_key(self, value):
        """
        Validate secret key format.
        
        Rules:
        - Must start with a letter
        - Only uppercase letters, numbers, and underscores
        - Minimum 1 character
        """
        value = value.strip().upper()
        
        if not value:
            raise serializers.ValidationError("Key cannot be empty")
        
        if not re.match(r'^[A-Z][A-Z0-9_]*$', value):
            raise serializers.ValidationError(
                "Key must start with a letter and contain only uppercase letters, numbers, and underscores"
            )
        
        return value
    
    def validate_value(self, value):
        """Validate that value is not empty (encrypted blobs are opaque)"""
        if not value:
            raise serializers.ValidationError("Value cannot be empty")
        
        return value


class SecretOutputSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    key = serializers.CharField(read_only=True)
    value = serializers.CharField(read_only=True,)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class SecretsBulkCreateSerializer(serializers.Serializer):
    project_id = serializers.UUIDField()
    environment = serializers.ChoiceField(choices=['development', 'staging', 'production'], default='development')
    secrets = serializers.DictField(child=serializers.CharField())
    
    def validate_secrets(self, value):
        """Validate secrets dictionary is not empty and within limits"""
        if not value:
            raise serializers.ValidationError("Secrets dictionary cannot be empty")
            
        if len(value) > 100:
            raise serializers.ValidationError("Cannot process more than 100 secrets in a single request")
        
        # Check for invalid keys
        for key in value.keys():
            key = key.strip().upper()
            if not key:
                raise serializers.ValidationError("Key cannot be empty")
            if not re.match(r'^[A-Z][A-Z0-9_]*$', key):
                raise serializers.ValidationError(
                    f"Invalid key '{key}': Must start with a letter and contain only uppercase letters, numbers, and underscores"
                )
        
        return value


class SecretsListOutputSerializer(serializers.Serializer):
    project_id = serializers.UUIDField(read_only=True)
    secrets = SecretOutputSerializer(many=True, read_only=True)


class SecretDetailSerializer(serializers.Serializer):
    """
    Serializer for single secret detail operations (get/update/delete).
    """
    id = serializers.UUIDField(read_only=True)
    environment = serializers.ChoiceField(choices=['development', 'staging', 'production'], required=False, default='development')
    key = serializers.CharField(max_length=255)
    value = serializers.CharField(required=False)
    
    def validate_key(self, value):
        """Validate and normalize key"""
        value = value.strip().upper()
        
        if not value:
            raise serializers.ValidationError("Key cannot be empty")
        
        if not re.match(r'^[A-Z][A-Z0-9_]*$', value):
            raise serializers.ValidationError("Key must start with a letter and contain only uppercase letters, numbers, and underscores")
        
        return value


class ProjectInviteSerializer(serializers.Serializer):
    """
    Serializer for inviting a user to a project.
    
    When inviting to a project in a personal workspace:
    - CLI generates new workspace key
    - CLI re-encrypts secrets with new key
    - API creates shared workspace, moves project
    """
    email = serializers.EmailField(
        help_text="Email of the user to invite"
    )
    role = serializers.ChoiceField(
        choices=['admin', 'member', 'read_only'],
        default='member',
        help_text="Role for the invitee in the shared workspace"
    )
    # Required for invitee (always)
    encrypted_workspace_key_invitee = serializers.CharField(
        help_text="Workspace key encrypted for the invitee"
    )
    # Optional - only sent when migrating from personal workspace
    encrypted_workspace_key_owner = serializers.CharField(
        required=False,  # ← Make optional
        allow_blank=True,
        help_text="Workspace key encrypted for the owner (only for migration)"
    )
    secrets = SecretItemSerializer(
        many=True,
        required=False,  # ← Already optional, good!
        help_text="Re-encrypted secrets (only for migration from personal workspace)"
    )