import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MigrationTokenResponseDataSchema(BaseModel):
    token: str
    expires_at: str
    user_email: str
    workspace_count: int


class SecretExportItemSchema(BaseModel):
    id: str
    project_id: str
    environment: str
    key: str
    client_ciphertext: str
    policy: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ProjectExportItemSchema(BaseModel):
    id: str
    name: str
    workspace_id: str
    created_at: Optional[str] = None
    secrets: List[SecretExportItemSchema] = Field(default_factory=list)


class AgentTokenExportItemSchema(BaseModel):
    id: str
    registration_id: str
    token_hash: str
    label: Optional[str] = None
    environment: str
    revoked_at: Optional[str] = None
    expires_at: Optional[str] = None
    created_at: Optional[str] = None


class AgentRegistrationExportItemSchema(BaseModel):
    id: str
    workspace_id: str
    project_id: Optional[str] = None
    name: str
    capabilities: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    tokens: List[AgentTokenExportItemSchema] = Field(default_factory=list)


class WorkspaceMemberExportItemSchema(BaseModel):
    user_email: str
    role: str
    joined_at: Optional[str] = None
    encrypted_workspace_key: Optional[str] = None


class WorkspaceAllowlistExportItemSchema(BaseModel):
    domain: str
    added_by_email: Optional[str] = None
    added_at: Optional[str] = None


class WorkspaceExportItemSchema(BaseModel):
    id: str
    name: str
    type: Optional[str] = None
    owner_email: str
    members: List[WorkspaceMemberExportItemSchema] = Field(default_factory=list)
    allowlist: List[WorkspaceAllowlistExportItemSchema] = Field(default_factory=list)
    projects: List[ProjectExportItemSchema] = Field(default_factory=list)
    agents: List[AgentRegistrationExportItemSchema] = Field(default_factory=list)


class UserProfileExportItemSchema(BaseModel):
    email: str
    first_name: str
    last_name: str
    password_hash: str
    key_salt: Optional[str] = None
    public_key: Optional[str] = None
    encrypted_private_key: Optional[str] = None


class MigrationExportBundleSchema(BaseModel):
    version: str = "1.0"
    exported_at: str
    user: UserProfileExportItemSchema
    workspaces: List[WorkspaceExportItemSchema] = Field(default_factory=list)


class MigrationImportRequestSchema(BaseModel):
    token: Optional[str] = None
    source_url: Optional[str] = None
    bundle: Optional[MigrationExportBundleSchema] = None


class MigrationImportResultSchema(BaseModel):
    workspaces_imported: int
    projects_imported: int
    secrets_imported: int
    agents_imported: int
    allowlist_entries_imported: int


class MigrationImportResponseDataSchema(BaseModel):
    status: str
    user_email: str
    summary: MigrationImportResultSchema
