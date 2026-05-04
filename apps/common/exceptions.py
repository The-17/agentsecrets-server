# Standard library
from http import HTTPStatus

# Third-party
from ninja.responses import Response


class ErrorCode:

    # AUTHENTICATION ERRORS
    INVALID_CREDENTIALS = "invalid_credentials"
    INVALID_TOKEN = "invalid_token"
    EXPIRED_TOKEN = "expired_token"
    UNAUTHORIZED = "unauthorized"
    UNVERIFIED_USER = "unverified_user"

    # AUTHORIZATION ERRORS
    FORBIDDEN = "forbidden"
    INSUFFICIENT_PERMISSIONS = "insufficient_permissions"

    # VALIDATION ERRORS
    INVALID_ENTRY = "invalid_entry"
    VALIDATION_ERROR = "validation_error"
    INVALID_VALUE = "invalid_value"

    # RESOURCE ERRORS
    NON_EXISTENT = "non_existent"
    ALREADY_EXISTS = "already_exists"

    # WORKSPACE-SPECIFIC ERRORS
    WORKSPACE_NOT_FOUND = "workspace_not_found"
    WORKSPACE_PERSONAL_DELETE = "workspace_personal_delete"
    WORKSPACE_LAST_ADMIN = "workspace_last_admin"

    # PROJECT-SPECIFIC ERRORS
    PROJECT_NOT_FOUND = "project_not_found"
    PROJECT_ALREADY_EXISTS = "project_already_exists"

    # SECRET-SPECIFIC ERRORS
    SECRET_NOT_FOUND = "secret_not_found"
    SECRET_DECRYPT_FAILED = "secret_decrypt_failed"
    INVALID_ENVIRONMENT = "invalid_environment"

    # MEMBER-SPECIFIC ERRORS
    MEMBER_NOT_FOUND = "member_not_found"
    MEMBER_ALREADY_EXISTS = "member_already_exists"
    MEMBER_CANNOT_REMOVE_OWNER = "member_cannot_remove_owner"
    MEMBER_CANNOT_CHANGE_OWNER = "member_cannot_change_owner"

    # AGENT-SPECIFIC ERRORS
    AGENT_NOT_FOUND = "agent_not_found"
    AGENT_TOKEN_NOT_FOUND = "agent_token_not_found"
    AGENT_TOKEN_EXPIRED = "agent_token_expired"
    AGENT_TOKEN_REVOKED = "agent_token_revoked"
    AGENT_TOKEN_INVALID = "agent_token_invalid"

    # ALLOWLIST ERRORS
    ALLOWLIST_DOMAIN_EXISTS = "allowlist_domain_exists"
    ALLOWLIST_DOMAIN_NOT_FOUND = "allowlist_domain_not_found"

    # ENCRYPTION ERRORS
    ENCRYPTION_KEY_MISSING = "encryption_key_missing"
    ENCRYPTION_FAILED = "encryption_failed"

    # GENERAL ERRORS
    SERVER_ERROR = "server_error"
    RATE_LIMITED = "rate_limited"


class RequestError(Exception):
    default_detail = "An error occurred"

    def __init__(self, err_code: str, err_msg: str, status_code: int = 400, data: dict = None) -> None:
        self.status_code = HTTPStatus(status_code)
        self.err_code = err_code
        self.err_msg = err_msg
        self.data = data
        super().__init__(err_msg)


class BodyValidationError(RequestError):
    def __init__(self, field: str, field_err_msg: str):
        super().__init__(ErrorCode.INVALID_ENTRY, "Invalid Entry", 422, {field: field_err_msg})


class NotFoundError(RequestError):
    def __init__(self, err_msg: str = "Resource not found"):
        super().__init__(ErrorCode.NON_EXISTENT, err_msg, 404)


class AuthenticationError(RequestError):
    def __init__(self, err_msg: str = "Authentication failed", err_code: str = ErrorCode.INVALID_CREDENTIALS):
        super().__init__(err_code, err_msg, 401)


class AuthorizationError(RequestError):
    def __init__(self, err_msg: str = "You don't have permission to perform this action"):
        super().__init__(ErrorCode.FORBIDDEN, err_msg, 403)


class ConflictError(RequestError):
    def __init__(self, err_msg: str = "Resource already exists"):
        super().__init__(ErrorCode.ALREADY_EXISTS, err_msg, 409)


# ==========================================
# EXCEPTION HANDLERS
# ==========================================

def validation_errors(request, exc):
    details = exc.errors
    modified_details = {}

    for error in details:
        field_name = error["loc"][-1]
        err_msg = error["msg"]
        err_type = error["type"]

        if err_type == "string_too_short":
            err_msg = f"Minimum {error['ctx']['min_length']} characters required"
        elif err_type == "string_too_long":
            err_msg = f"Maximum {error['ctx']['max_length']} characters allowed"
        elif err_type == "missing":
            err_msg = "This field is required"
        elif "enum" in err_type:
            allowed = error.get("ctx", {}).get("expected", "")
            err_msg = f"Invalid choice. Allowed values: {allowed}"

        modified_details[f"{field_name}"] = err_msg

    return Response(
        {
            "status": "failure",
            "code": ErrorCode.INVALID_ENTRY,
            "message": "Invalid Entry",
            "data": modified_details,
        },
        status=422,
    )


def request_errors(request, exc):
    err_dict = {
        "status": "failure",
        "code": exc.err_code,
        "message": exc.err_msg,
    }
    if exc.data:
        err_dict["data"] = exc.data

    return Response(err_dict, status=exc.status_code)
