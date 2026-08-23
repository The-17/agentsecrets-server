from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class BaseBillingProvider(ABC):
    """Abstract interface for payment & billing gateways."""

    @abstractmethod
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
        """Generates a checkout URL where the user enters payment details."""
        pass

    @abstractmethod
    def verify_webhook(self, payload: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        """Validates gateway HMAC signature and extracts normalized {workspace_id, status, event_type}."""
        pass
