import hmac
import hashlib
import json
import requests
from typing import Any, Dict
from django.conf import settings
from apps.common.exceptions import RequestError, ErrorCode
from .base import BaseBillingProvider

class PaystackBillingProvider(BaseBillingProvider):
    """Paystack payment gateway adapter for card, apple pay, and recurring subscriptions."""

    def __init__(self):
        self.secret_key = getattr(settings, "PAYSTACK_SECRET_KEY", "")
        self.base_url = "https://api.paystack.co"

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
        if not self.secret_key:
            raise RequestError(ErrorCode.SERVER_ERROR, "PAYSTACK_SECRET_KEY is not configured in server settings")

        payload = {
            "email": email,
            "amount": amount_cents * 100,  # Paystack expects amounts in lowest currency unit
            "callback_url": return_url,
            "metadata": {
                "workspace_id": workspace_id,
                "workspace_name": workspace_name,
                "plan_name": plan_name,
            },
        }

        resp = requests.post(
            f"{self.base_url}/transaction/initialize",
            headers={"Authorization": f"Bearer {self.secret_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=10,
        )

        data = resp.json()
        if not data.get("status"):
            raise RequestError(ErrorCode.SERVER_ERROR, f"Paystack initialization failed: {data.get('message', 'Unknown error')}")

        return data["data"]["authorization_url"]

    def verify_webhook(self, payload: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        signature = headers.get("x-paystack-signature", headers.get("X-Paystack-Signature", ""))
        if not signature or not self.secret_key:
            raise RequestError(ErrorCode.INVALID_ENTRY, "Missing or invalid Paystack webhook signature")

        expected_sig = hmac.new(self.secret_key.encode("utf-8"), payload, hashlib.sha512).hexdigest()
        if signature != expected_sig:
            raise RequestError(ErrorCode.INVALID_ENTRY, "Paystack HMAC signature mismatch")

        body = json.loads(payload.decode("utf-8"))
        event_type = body.get("event")
        data = body.get("data", {})
        metadata = data.get("metadata", {})
        workspace_id = metadata.get("workspace_id")

        return {
            "event": event_type,
            "workspace_id": workspace_id,
            "status": "active" if event_type == "charge.success" else "past_due",
            "customer_code": data.get("customer", {}).get("customer_code"),
            "subscription_code": data.get("subscription_code"),
        }
