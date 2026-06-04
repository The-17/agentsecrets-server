# Standard library
import re
from typing import Optional, List, Literal

# Third-party
from ninja import Schema
from pydantic import EmailStr, field_validator

# Local
from apps.workspaces.models import MembershipRole


# Pre-compiled domain validation pattern (RFC 1035 compliant)
DOMAIN_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)


# ==========================================
# WORKSPACE SCHEMAS
# ==========================================

class WorkspaceCreateSchema(Schema):
    name: str
    encrypted_workspace_key: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Workspace name must be at least 2 characters")
        return v


class WorkspaceUpdateSchema(Schema):
    name: Optional[str] = None


# ==========================================
# MEMBER SCHEMAS
# ==========================================

class MemberInviteSchema(Schema):
    email: EmailStr
    role: Literal["admin", "member", "read_only"] = "member"
    encrypted_workspace_key: str


class InviteEntrySchema(Schema):
    email: EmailStr
    role: Literal["admin", "member", "read_only"] = "member"
    encrypted_workspace_key: str


class BatchInviteSchema(Schema):
    invites: List[InviteEntrySchema]


class MemberUpdateSchema(Schema):
    role: Literal["admin", "member", "read_only"]


class MemberRoleActionSchema(Schema):
    action: Literal["promote", "demote"]


# ==========================================
# ALLOWLIST SCHEMAS
# ==========================================

class AllowlistBulkCreateSchema(Schema):
    domains: List[str]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v):
        if not v:
            raise ValueError("Domains list cannot be empty")
        valid = []
        for domain in v:
            d = domain.replace("https://", "").replace("http://", "")
            d = d.split("/")[0]
            if not DOMAIN_PATTERN.match(d):
                raise ValueError(f"Invalid domain format: {domain}")
            valid.append(d.lower())
        return list(set(valid))


# ==========================================
# AGENT SCHEMAS
# ==========================================

class AgentCreateSchema(Schema):
    name: str
    label: Optional[str] = None
    expires_in_days: Optional[int] = None


class AgentTokenCreateSchema(Schema):
    label: Optional[str] = None
    expires_in_days: Optional[int] = None


class AgentCapabilitiesSchema(Schema):
    allowed_secrets: List[str] = []
    denied_secrets: List[str] = []


# ==========================================
# AUDIT LOG SCHEMAS
# ==========================================

class InternalAgentVerifySchema(Schema):
    token_id: Optional[str] = None
    token: str
