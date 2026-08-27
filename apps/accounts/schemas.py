from typing import Optional, List
import unicodedata
from ninja import Schema
from pydantic import ConfigDict, EmailStr, field_validator


def sanitize_and_normalize_password(v: str, *, min_length: int = 0) -> str:
    """
    Validates and normalizes password inputs:
    - Rejects null bytes to prevent C-level string truncation attacks.
    - Caps length at 4096 characters to prevent memory-allocation DoS.
    - Normalizes Unicode using NFKC to ensure canonical glyph representation.
    - Enforces optional minimum length (default 8 chars for write operations).
    """
    if "\x00" in v:
        raise ValueError("Password must not contain null bytes")
    if len(v) > 4096:
        raise ValueError("Password exceeds maximum allowed length of 4096 characters")
    normalized = unicodedata.normalize("NFKC", v)
    if min_length > 0 and len(normalized) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters")
    return normalized


# ==========================================
# REQUEST SCHEMAS
# ==========================================

class RegisterSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    first_name: str
    last_name: str
    email: EmailStr
    password: str
    key_salt: str
    terms_agreement: bool
    public_key: Optional[str] = None
    encrypted_private_key: Optional[str] = None

    @field_validator("first_name", "last_name")
    @classmethod
    def no_spaces(cls, v: str) -> str:
        if " " in v.strip():
            raise ValueError("No spacing allowed")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return sanitize_and_normalize_password(v, min_length=8)

    @field_validator("terms_agreement")
    @classmethod
    def must_agree(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must agree to terms and conditions")
        return v


class LoginSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return sanitize_and_normalize_password(v, min_length=0)


class LogoutSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    refresh_token: Optional[str] = None


class VerifyOtpSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    otp: int


class ResendOtpSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class ResetPasswordSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class SetNewPasswordSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    password: str
    confirm_password: str
    token: str
    uidb64: str
    key_salt: Optional[str] = None
    encrypted_private_key: Optional[str] = None

    @field_validator("password", "confirm_password")
    @classmethod
    def validate_passwords(cls, v: str) -> str:
        return sanitize_and_normalize_password(v, min_length=8)


class ChangePasswordSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    current_password: str
    new_password: str
    key_salt: str
    encrypted_private_key: str

    @field_validator("current_password")
    @classmethod
    def validate_current_password(cls, v: str) -> str:
        return sanitize_and_normalize_password(v, min_length=0)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return sanitize_and_normalize_password(v, min_length=8)


class RefreshTokenSchema(Schema):
    model_config = ConfigDict(extra="forbid")

    refresh: str


# ==========================================
# RESPONSE SCHEMAS
# ==========================================

class WorkspaceSummarySchema(Schema):
    id: str
    name: str
    type: str
    role: Optional[str] = None
    encrypted_workspace_key: Optional[str] = None


class UserSummarySchema(Schema):
    id: str
    email: str
    first_name: str
    last_name: str
    public_key: Optional[str] = None


class RegisterResponseDataSchema(Schema):
    email: str
    first_name: str
    last_name: str
    workspace: Optional[WorkspaceSummarySchema] = None


class LoginResponseDataSchema(Schema):
    access: str
    refresh: str
    expires_at: str
    key_salt: Optional[str] = None
    encrypted_private_key: Optional[str] = None
    user: UserSummarySchema
    workspaces: List[WorkspaceSummarySchema]


class TokenRefreshResponseDataSchema(Schema):
    access: str
    expires_at: str
    refresh: Optional[str] = None


class UserPublicKeyResponseSchema(Schema):
    email: str
    public_key: str
