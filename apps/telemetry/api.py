# Third-party
from ninja_extra import NinjaExtraAPI
from ninja.errors import ValidationError

# Local
from apps.common.exceptions import RequestError, validation_errors, request_errors
from .views import TelemetryController

telemetry_api = NinjaExtraAPI(
    title="AgentSecrets Telemetry API",
    version="1.0.0",
    description="Telemetry ingestion and metrics endpoints",
    auth=None,
    urls_namespace="telemetry",
)

# Register standard exception handlers
telemetry_api.exception_handler(ValidationError)(validation_errors)
telemetry_api.exception_handler(RequestError)(request_errors)

# Register TelemetryController explicitly to prevent auto_discover_controllers cross-registration
telemetry_api.register_controllers(TelemetryController)
