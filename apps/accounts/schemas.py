# Standard library
from typing import Optional

# Third-party
from ninja import Schema
from pydantic import EmailStr, field_validator


# ==========================================
# REQUEST SCHEMAS
# ==========================================

class RegisterSchema(Schema):
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
    def no_spaces(cls, v):
        if " " in v.strip():
            raise ValueError("No spacing allowed")
        return v

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("terms_agreement")
    @classmethod
    def must_agree(cls, v):
        if not v:
            raise ValueError("You must agree to terms and conditions")
        return v


class LoginSchema(Schema):
    email: EmailStr
    password: str


class LogoutSchema(Schema):
    refresh_token: str


class VerifyOtpSchema(Schema):
    email: EmailStr
    otp: int


class ResendOtpSchema(Schema):
    email: EmailStr


class ResetPasswordSchema(Schema):
    email: EmailStr


class SetNewPasswordSchema(Schema):
    password: str
    confirm_password: str
    token: str
    uidb64: str
    key_salt: Optional[str] = None
    encrypted_private_key: Optional[str] = None

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class ChangePasswordSchema(Schema):
    current_password: str
    new_password: str
    key_salt: str
    encrypted_private_key: str

    @field_validator("new_password")
    @classmethod
    def password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class RefreshTokenSchema(Schema):
    refresh: str
