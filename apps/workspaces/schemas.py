import re
from typing import Optional, List, Literal, Dict, Any
from ninja import Schema
from pydantic import ConfigDict, EmailStr, field_validator


# Pre-compiled domain validation pattern (RFC 1035 compliant)
DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


# ==========================================
# REQUEST SCHEMAS
# ==========================================

class WorkspaceCreateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    name: str
    encrypted_workspace_key: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Workspace name must be at least 2 characters")
        return v


class WorkspaceUpdateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None


class MemberInviteSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    role: Literal["admin", "member", "read_only"] = "member"
    encrypted_workspace_key: str


class InviteEntrySchema(Schema):
    model_config = ConfigDict(extra="ignore")

    email: EmailStr
    role: str = "member"
    encrypted_workspace_key: Optional[str] = ""

    @field_validator("role", mode="before")
    @classmethod
    def normalize_role(cls, v: str) -> str:
        if not v:
            return "member"
        v_clean = str(v).strip().lower()
        if v_clean in ["developer", "member"]:
            return "member"
        if v_clean in ["admin", "administrator"]:
            return "admin"
        if v_clean in ["viewer", "read_only", "readonly"]:
            return "read_only"
        return "member"


class BatchInviteSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    invites: List[InviteEntrySchema]


class MemberUpdateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    role: Literal["admin", "member", "read_only"]


class MemberRoleActionSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    action: Literal["promote", "demote"]


class AllowlistBulkCreateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    domains: List[str]

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v: List[str]) -> List[str]:
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


class AgentCreateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    name: str
    label: Optional[str] = None
    expires_in_days: Optional[int] = None


class AgentTokenCreateSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    label: Optional[str] = None
    expires_in_days: Optional[int] = None


class AgentCapabilitiesSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    allowed_secrets: List[str] = []
    denied_secrets: List[str] = []


class InternalAgentVerifySchema(Schema):
    model_config = ConfigDict(extra="forbid")

    token_id: Optional[str] = None
    token: str


# ==========================================
# RESPONSE SCHEMAS
# ==========================================

class WorkspaceItemSchema(Schema):
    id: str
    name: str
    type: str
    role: str
    billing_id: Optional[str] = None
    encrypted_workspace_key: str
    created_at: Optional[str] = None


class WorkspaceDetailSchema(Schema):
    id: str
    name: str
    type: str
    role: str
    billing_id: Optional[str] = None
    encrypted_workspace_key: str
    created_at: str
    updated_at: str


class WorkspaceSimpleSchema(Schema):
    id: str
    name: str
    type: str
    role: Optional[str] = None


class MemberItemSchema(Schema):
    id: str
    user_id: str
    email: str
    name: str
    role: str
    status: str
    created_at: Optional[str] = None


class InviteResultItemSchema(Schema):
    email: str
    error: str = ""


class MemberRoleUpdateResponseSchema(Schema):
    user_id: str
    email: Optional[str] = None
    role: str


class AllowlistItemSchema(Schema):
    id: str
    domain: str
    added_by_email: Optional[str] = None
    added_at: Optional[str] = None


class AllowlistLogItemSchema(Schema):
    domain: str
    action: str
    performed_by_email: Optional[str] = None
    performed_at: Optional[str] = None


class AgentItemSchema(Schema):
    id: str
    name: str
    project_id: Optional[str] = None
    token_count: int = 0
    active_token_count: int = 0
    last_used_at: Optional[str] = None
    created_at: str


class AgentCreatedResponseDataSchema(Schema):
    agent: AgentItemSchema
    token: str
    token_id: str


class AgentTokenItemSchema(Schema):
    id: str
    label: Optional[str] = None
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None
    created_at: str


class AgentTokenCreatedResponseDataSchema(Schema):
    token: str
    token_id: str
    token_metadata: Dict[str, Any]


class AgentVerifyResponseSchema(Schema):
    valid: bool
    reason: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    workspace_id: Optional[str] = None
    project_id: Optional[str] = None
    environment: Optional[str] = None
    capabilities: Optional[Dict[str, Any]] = None
    token_id: Optional[str] = None
    billing_id: Optional[str] = None
    allowlist: Optional[List[str]] = None


class AuditLogItemSchema(Schema):
    id: str
    timestamp: Optional[str] = None
    agent_id: Optional[str] = None
    identity_level: Optional[str] = None
    credential_ref: Optional[str] = None
    injection_style: Optional[str] = None
    target_domain: Optional[str] = None
    target_url: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    duration_ms: Optional[int] = None
    redacted: Optional[bool] = None
    resolution_path: Optional[str] = None
    error: Optional[str] = None
    source: Optional[str] = "cloud"


class AuditSummaryResponseSchema(Schema):
    period: Dict[str, Any]
    totals: Dict[str, int]
    by_agent: List[Dict[str, Any]]
    by_credential: List[Dict[str, Any]]
    by_domain: List[Dict[str, Any]]
    anonymous_call_count: int


class WorkspaceActivityItemSchema(Schema):
    id: str
    workspace_id: str
    project_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    metadata: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    source: str = "api"
    created_at: str


class ForensicDecisionReplaySchema(Schema):
    id: str
    workspace_id: str
    project_id: Optional[str] = None
    stream_id: str
    stream_seq: int
    prev_chain_hash: Optional[str] = None
    chain_hash: Optional[str] = None
    entry_hash: Optional[str] = None
    created_at: str
    event: Dict[str, Any] = {}
    snapshot: Dict[str, Any] = {}
    enforcement: Dict[str, Any] = {}
    resolution: Dict[str, Any] = {}
    steps: Dict[str, Any] = {}
    verified: bool = True

