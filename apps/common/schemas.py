from typing import Optional, Generic, TypeVar
from ninja import Schema

T = TypeVar("T")

# ==========================================
# SHARED TYPES
# ==========================================

# Environment names are validated slugs, not a closed set. A project owns the three
# standard names plus any custom name it has stored secrets under. The rule lives in
# apps.secrets_app.environment; the resolver, not this control plane, decides entitlement.
EnvironmentType = str


# ==========================================
# STANDARD RESPONSE SCHEMAS
# ==========================================

class SuccessResponse(Schema):
    status: str = "success"
    message: str


class ErrorResponse(Schema):
    status: str = "error"
    message: str


class DataResponse(Schema, Generic[T]):
    status: str = "success"
    message: str
    data: Optional[T] = None
