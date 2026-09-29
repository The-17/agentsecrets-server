import re
import uuid
from typing import Optional, Dict, List, Literal, Any
from ninja import Schema
from pydantic import ConfigDict, field_validator, EmailStr

from apps.common.schemas import EnvironmentType


# ==========================================
# REQUEST SCHEMAS
# ==========================================

class ProjectCreateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: Optional[str] = None
    workspace_id: uuid.UUID

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) < 2:
            raise ValueError("Project name must be at least 2 characters")
        if not re.match(r"^[a-z0-9_-]+$", value):
            raise ValueError("Project name can only contain letters, numbers, hyphens, and underscores")
        return value


class ProjectUpdateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip().lower()
        if len(value) < 2:
            raise ValueError("Project name must be at least 2 characters")
        if not re.match(r"^[a-z0-9_-]+$", value):
            raise ValueError("Project name can only contain letters, numbers, hyphens, and underscores")
        return value


class SecretItemSchema(Schema):
    """Used in project invite for re-encrypted secrets."""
    model_config = ConfigDict(extra="forbid")

    environment: EnvironmentType = "development"
    key: str
    value: str


class ProjectInviteSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    role: Literal["admin", "member", "read_only"] = "member"
    encrypted_workspace_key_invitee: str
    encrypted_workspace_key_owner: Optional[str] = None
    secrets: List[SecretItemSchema] = []


class SecretBulkUpsertSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    project_id: uuid.UUID
    environment: EnvironmentType = "development"
    secrets: Dict[str, str]

    @field_validator("secrets")
    @classmethod
    def validate_secrets(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not value:
            raise ValueError("Secrets dictionary cannot be empty")
        if len(value) > 100:
            raise ValueError("Cannot process more than 100 secrets in a single request")
        for key in value.keys():
            key_upper = key.strip().upper()
            if not key_upper:
                raise ValueError("Key cannot be empty")
            if not re.match(r"^[A-Z][A-Z0-9_]*$", key_upper):
                raise ValueError(
                    f"Invalid key '{key_upper}': Must start with a letter and contain only uppercase letters, numbers, and underscores"
                )
        return value


class SecretUpdateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    value: str


class SecretVersionCreateSchema(Schema):
    """Stage a client-encrypted value as pending. Ciphertext is the client's
    DEK-ciphertext; the server applies only its own envelope."""
    model_config = ConfigDict(extra="forbid")

    ciphertext: str
    rotation_id: Optional[str] = None
    reason: str = "routine"  # routine | compromise


class SecretPromoteSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    expected_current_version_id: Optional[str] = None
    reason: str = "routine"  # routine | compromise (compromise shreds previous)


class SecretRotationPolicySchema(Schema):
    model_config = ConfigDict(extra="forbid")

    rotation_type: str = "value_client"  # value_client | value_auto | value_provider
    period_days: Optional[int] = None
    overlap_hours: Optional[int] = None
    provider_binding: Optional[Dict[str, Any]] = None
    enabled: bool = True


class ValueExecuteSchema(Schema):
    """B2 autonomous execute (resolver-signed): stage a resolver-encrypted
    value and promote it atomically. Ciphertext is the resolver's DEK
    ciphertext; the server applies only its own envelope."""
    model_config = ConfigDict(extra="forbid")

    workspace_id: str
    project_id: str
    environment: str = "development"
    key: str
    ciphertext: str
    rotation_id: str
    reason: str = "routine"
    overlap_hours: Optional[int] = None


# ==========================================
# RESPONSE SCHEMAS
# ==========================================

class ProjectResponseDataSchema(Schema):
    id: str
    workspace_id: str
    workspace_name: str
    name: str
    description: str = ""
    total_secrets: Optional[int] = 0


class ProjectInviteResponseDataSchema(Schema):
    workspace_id: str
    workspace_name: str
    workspace_type: str
    invitee_email: str
    invitee_role: str
    migrated_from_personal: bool


class EnvironmentCountItemSchema(Schema):
    secret_count: int


class ProjectEnvironmentsResponseDataSchema(Schema):
    project_id: str
    environments: Dict[str, EnvironmentCountItemSchema]


class SecretCoverageItemSchema(Schema):
    key_name: str
    development: bool
    staging: bool
    production: bool


class ProjectSecretsCoverageResponseDataSchema(Schema):
    project_id: str
    keys: List[SecretCoverageItemSchema]


class SecretsDiffResponseDataSchema(Schema):
    in_from_only: List[str]
    in_to_only: List[str]
    in_both: List[str]


class SecretBulkUpsertResponseDataSchema(Schema):
    created: int
    updated: int
    total: int
    environment: str


class SecretRecordSchema(Schema):
    id: str
    key: str
    value: str
    policy: Dict[str, Any] = {}


class SecretListResponseDataSchema(Schema):
    project_id: str
    workspace_id: Optional[str] = None
    workspace_name: Optional[str] = None
    secrets: List[SecretRecordSchema]

class SecretReencryptedItemSchema(Schema):
    id: uuid.UUID
    value: str


class ProjectTransferSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    target_workspace_id: uuid.UUID
    secrets: List[SecretReencryptedItemSchema] = []


class ProjectTransferResponseDataSchema(Schema):
    project_id: str
    project_name: str
    source_workspace_id: str
    source_workspace_name: str
    target_workspace_id: str
    target_workspace_name: str
    secrets_transferred: int


class SecretVersionItemSchema(Schema):
    """Rotation metadata only — ciphertext is never serialized (HR-H1)."""
    version_id: str
    staging_label: str
    rotation_reason: str
    rotation_id: Optional[str] = None
    overlap_until: Optional[str] = None
    revoked_at: Optional[str] = None
    created_at: str


class SecretPendingResponseDataSchema(Schema):
    version_id: str
    staging_label: str
    rotation_reason: str
    rotation_id: Optional[str] = None
    overlap_until: Optional[str] = None
    revoked_at: Optional[str] = None
    created_at: str
    replayed: bool = False


class SecretPromoteResponseDataSchema(Schema):
    key: str
    environment: str
    current_version_id: str
    previous_version_id: Optional[str] = None
    reason: str


class SecretRollbackResponseDataSchema(Schema):
    key: str
    environment: str
    current_version_id: str
    previous_version_id: str


class SecretRotationPolicyDataSchema(Schema):
    key: str
    environment: str
    policy: Dict[str, Any]


class SecretRotationStatusDataSchema(Schema):
    key: str
    environment: str
    policy: Dict[str, Any]
    versions: List[SecretVersionItemSchema]


class DueValueRotationItemSchema(Schema):
    secret_id: str
    project_id: str
    environment: str
    key: str
    rotation_type: str
    rotation_period_days: Optional[int] = None
    next_rotation_at: Optional[str] = None
    rotation_binding: Dict[str, Any] = {}
