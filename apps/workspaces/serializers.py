# Standard library
import re

# Third-party
from rest_framework import serializers

# Local
from .models import (
    Workspace, Membership, WorkspaceType, MembershipRole, MembershipStatus,
    WorkspaceAllowlist, WorkspaceAllowlistLog
)

# Pre-compiled domain validation pattern (RFC 1035 compliant)
DOMAIN_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)


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


class WorkspaceAllowlistSerializer(serializers.ModelSerializer):
    added_by_email = serializers.EmailField(
        source='added_by.email',
        read_only=True
    )

    class Meta:
        model = WorkspaceAllowlist
        fields = ['id', 'domain', 'added_by_email', 'added_at']
        read_only_fields = ['id', 'added_by_email', 'added_at']

    def validate_domain(self, value):
        # Strip protocol if user accidentally includes it
        value = value.replace('https://', '').replace('http://', '')
        # Strip trailing slashes and paths
        value = value.split('/')[0]
        # Domain format validation
        if not DOMAIN_PATTERN.match(value):
            raise serializers.ValidationError("Invalid domain format.")
        return value.lower()


class WorkspaceAllowlistBulkCreateSerializer(serializers.Serializer):
    domains = serializers.ListField(
        child=serializers.CharField(max_length=253),
        allow_empty=False
    )
    
    def validate_domains(self, value):
        valid_domains = []
        
        for domain in value:
            # Strip protocol if user accidentally includes it
            d = domain.replace('https://', '').replace('http://', '')
            # Strip trailing slashes and paths
            d = d.split('/')[0]
            
            if not DOMAIN_PATTERN.match(d):
                raise serializers.ValidationError(f"Invalid domain format: {domain}")
            
            valid_domains.append(d.lower())
            
        return list(set(valid_domains))


class WorkspaceAllowlistLogSerializer(serializers.ModelSerializer):
    performed_by_email = serializers.EmailField(
        source='performed_by.email',
        read_only=True
    )

    class Meta:
        model = WorkspaceAllowlistLog
        fields = ['domain', 'action', 'performed_by_email', 'performed_at']
