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
        """
        value = value.strip()
        
        if len(value) < 2:
            raise serializers.ValidationError("Project name must be at least 2 characters")

        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
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
        """Validate that value is not empty"""
        if not value or not value.strip():
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
    secrets = SecretItemSerializer(many=True)
    
    def validate_secrets(self, value):
        """Validate secrets list is not empty"""
        if not value:
            raise serializers.ValidationError("Secrets list cannot be empty")
        
        # Check for duplicate keys
        keys = [s['key'] for s in value]
        if len(keys) != len(set(keys)):
            raise serializers.ValidationError("Duplicate secret keys are not allowed")
        
        return value


class SecretsListOutputSerializer(serializers.Serializer):
    project_id = serializers.UUIDField(read_only=True)
    secrets = SecretOutputSerializer(many=True, read_only=True)


class SecretDetailSerializer(serializers.Serializer):
    """
    Serializer for single secret detail operations (get/update/delete).
    """
    id = serializers.UUIDField(read_only=True)
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