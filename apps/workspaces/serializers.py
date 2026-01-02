# Third-party
from rest_framework import serializers

# Local
from .models import Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus


class WorkspaceSerializer(serializers.Serializer):
    """Serializer for workspace details"""
    id = serializers.UUIDField(read_only=True)
    name = serializers.CharField(max_length=255)
    type = serializers.ChoiceField(choices=WorkspaceType.choices, read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class WorkspaceCreateSerializer(serializers.Serializer):
    """Serializer for creating a new shared workspace"""
    name = serializers.CharField(max_length=255)
    encrypted_workspace_key = serializers.CharField(
        help_text="Workspace key encrypted with the creator's public key"
    )
    
    def validate_name(self, value):
        value = value.strip()
        if len(value) < 2:
            raise serializers.ValidationError("Workspace name must be at least 2 characters")
        return value


class WorkspaceListSerializer(serializers.Serializer):
    """Serializer for listing workspaces with membership info"""
    id = serializers.UUIDField()
    name = serializers.CharField()
    type = serializers.CharField()
    role = serializers.CharField()
    encrypted_workspace_key = serializers.CharField()
    created_at = serializers.DateTimeField()


class WorkspaceUpdateSerializer(serializers.Serializer):
    """Serializer for updating workspace details"""
    name = serializers.CharField(max_length=255, required=False)


class MembershipSerializer(serializers.Serializer):
    """Serializer for membership details"""
    id = serializers.UUIDField(read_only=True)
    user_id = serializers.UUIDField(source='user.id')
    user_email = serializers.EmailField(source='user.email')
    user_name = serializers.SerializerMethodField()
    role = serializers.ChoiceField(choices=MembershipRole.choices)
    status = serializers.ChoiceField(choices=MembershipStatus.choices, read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    
    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}"


class MemberInviteSerializer(serializers.Serializer):
    """Serializer for inviting a member to a workspace"""
    email = serializers.EmailField()
    role = serializers.ChoiceField(
        choices=[MembershipRole.ADMIN, MembershipRole.MEMBER, MembershipRole.READ_ONLY],
        default=MembershipRole.MEMBER
    )
    encrypted_workspace_key = serializers.CharField(
        help_text="Workspace key encrypted with the invitee's public key"
    )


class MemberUpdateSerializer(serializers.Serializer):
    """Serializer for updating a member's role"""
    role = serializers.ChoiceField(
        choices=[MembershipRole.ADMIN, MembershipRole.MEMBER, MembershipRole.READ_ONLY]
    )


class PublicKeySerializer(serializers.Serializer):
    """Serializer for returning a user's public key"""
    email = serializers.EmailField()
    public_key = serializers.CharField()
