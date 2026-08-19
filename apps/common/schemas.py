from typing import Literal, Optional, Any, Generic, TypeVar
from ninja import Schema

T = TypeVar("T")

# ==========================================
# SHARED TYPES
# ==========================================

EnvironmentType = Literal["development", "staging", "production"]


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
