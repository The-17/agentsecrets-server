# Standard library
import re
import uuid
from typing import Optional, Dict, List, Literal

# Third-party
from ninja import Schema
from pydantic import field_validator, EmailStr

# Local
from apps.common.schemas import EnvironmentType


# ==========================================
# PROJECT SCHEMAS
# ==========================================

class ProjectCreateSchema(Schema):
    name: str
    description: Optional[str] = None
    workspace_id: uuid.UUID

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        v = v.strip().lower()
        if len(v) < 2:
            raise ValueError("Project name must be at least 2 characters")
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError("Project name can only contain letters, numbers, hyphens, and underscores")
        return v


class ProjectUpdateSchema(Schema):
    name: Optional[str] = None
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v is None:
            return v
        v = v.strip().lower()
        if len(v) < 2:
            raise ValueError("Project name must be at least 2 characters")
        if not re.match(r'^[a-z0-9_-]+$', v):
            raise ValueError("Project name can only contain letters, numbers, hyphens, and underscores")
        return v


class SecretItemSchema(Schema):
    """Used in project invite for re-encrypted secrets."""
    environment: EnvironmentType = "development"
    key: str
    value: str


class ProjectInviteSchema(Schema):
    email: EmailStr
    role: Literal["admin", "member", "read_only"] = "member"
    encrypted_workspace_key_invitee: str
    encrypted_workspace_key_owner: Optional[str] = None
    secrets: List[SecretItemSchema] = []


# ==========================================
# SECRET SCHEMAS
# ==========================================

class SecretBulkUpsertSchema(Schema):
    project_id: uuid.UUID
    environment: EnvironmentType = "development"
    secrets: Dict[str, str]

    @field_validator("secrets")
    @classmethod
    def validate_secrets(cls, v):
        if not v:
            raise ValueError("Secrets dictionary cannot be empty")
        if len(v) > 100:
            raise ValueError("Cannot process more than 100 secrets in a single request")
        for key in v.keys():
            key_upper = key.strip().upper()
            if not key_upper:
                raise ValueError("Key cannot be empty")
            if not re.match(r'^[A-Z][A-Z0-9_]*$', key_upper):
                raise ValueError(
                    f"Invalid key '{key_upper}': Must start with a letter and contain only uppercase letters, numbers, and underscores"
                )
        return v


class SecretUpdateSchema(Schema):
    value: str
