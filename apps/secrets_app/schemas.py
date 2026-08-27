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


# ==========================================
# RESPONSE SCHEMAS
# ==========================================

class ProjectContributorItemSchema(Schema):
    id: str
    email: str
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    contributions_count: int = 1


class ProjectResponseDataSchema(Schema):
    id: str
    workspace_id: str
    workspace_name: str
    name: str
    description: str = ""
    environment_counts: Optional[Dict[str, int]] = None
    total_secrets: Optional[int] = None
    contributors: Optional[List[ProjectContributorItemSchema]] = None


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
    secrets: List[SecretRecordSchema]
