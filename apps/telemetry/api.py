# Third-party
from ninja_extra import NinjaExtraAPI

telemetry_api = NinjaExtraAPI(
    title="AgentSecrets Telemetry API",
    version="1.0.0",
    description="Telemetry ingestion and metrics endpoints",
    auth=None,
    urls_namespace="telemetry",
)

# Import the controller and register it explicitly to prevent auto_discover_controllers
# from scanning and registering other project controllers on this instance.
from .views import TelemetryController

telemetry_api.register_controllers(TelemetryController)
