from typing import Any, Dict
from .base import BaseBillingProvider

class DummyBillingProvider(BaseBillingProvider):
    """Sandbox provider for local dev testing with zero real money or external network calls."""

    def create_checkout_url(
        self,
        *,
        workspace_id: str,
        workspace_name: str,
        plan_name: str,
        email: str,
        amount_cents: int,
        return_url: str,
    ) -> str:
        # Returns instant simulated success callback
        sep = "&" if "?" in return_url else "?"
        return f"{return_url}{sep}simulated=true&plan={plan_name}&ws={workspace_id}"

    def verify_webhook(self, payload: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        return {
            "event": "charge.success",
            "workspace_id": headers.get("X-Mock-Workspace-Id", ""),
            "status": "active",
        }
