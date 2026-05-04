# Third-party
from ninja_extra import NinjaExtraAPI
from ninja.errors import ValidationError

# Local
from apps.common.auth import JWTAuth
from apps.common.exceptions import RequestError, validation_errors, request_errors

api = NinjaExtraAPI(
    title="AgentSecrets API",
    version="1.0.0",
    description="Secure secrets management API for AgentSecrets",
    auth=JWTAuth(),
)

# Register exception handlers
api.exception_handler(ValidationError)(validation_errors)
api.exception_handler(RequestError)(request_errors)

# Explicitly import all controllers so they register with the API.
# ninja-extra auto_discover looks for controllers.py by default,
# but our controllers live in views.py per project convention.
from apps.accounts.views import AuthController, UserController  # noqa: F401, E402
from apps.secrets_app.views import ProjectController, SecretsController  # noqa: F401, E402
from apps.workspaces.views import (  # noqa: F401, E402
    WorkspaceController, AllowlistController, AgentController,
    TokenController, AuditController, ResolverController,
)

api.auto_discover_controllers()
