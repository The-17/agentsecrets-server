# Standard library
from typing import Literal, Optional, Any

# Third-party
from ninja import Schema


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


class DataResponse(Schema):
    status: str = "success"
    message: str
    data: Any = None
