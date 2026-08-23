import hmac
import hashlib
import json
import requests
from typing import Any, Dict
from django.conf import settings
from apps.common.exceptions import RequestError, ErrorCode
from .base import BaseBillingProvider

class LemonSqueezyBillingProvider(BaseBillingProvider):
    """LemonSqueezy Merchant of Record (MoR) billing adapter for global SaaS subscriptions."""

    def __init__(self):
        self.api_key = getattr(settings, "LEMONSQUEEZY_API_KEY", "")
        self.store_id = getattr(settings, "LEMONSQUEEZY_STORE_ID", "")
        self.webhook_secret = getattr(settings, "LEMONSQUEEZY_WEBHOOK_SECRET", "")
        self.base_url = "https://api.lemonsqueezy.com/v1"

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
        if not self.api_key or not self.store_id:
            raise RequestError(
                ErrorCode.SERVER_ERROR,
                "LEMONSQUEEZY_API_KEY and LEMONSQUEEZY_STORE_ID must be configured in settings"
            )

        payload = {
            "data": {
                "type": "checkouts",
                "attributes": {
                    "checkout_data": {
                        "email": email,
                        "custom": {
                            "workspace_id": workspace_id,
                            "workspace_name": workspace_name,
                            "plan_name": plan_name,
                        }
                    },
                    "product_options": {
                        "redirect_url": return_url,
                    }
                },
                "relationships": {
                    "store": {
                        "data": {
                            "type": "stores",
                            "id": str(self.store_id)
                        }
                    }
                }
            }
        }

        resp = requests.post(
            f"{self.base_url}/checkouts",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Accept": "application/vnd.api+json",
                "Content-Type": "application/vnd.api+json"
            },
            json=payload,
            timeout=10,
        )

        data = resp.json()
        if resp.status_code >= 400 or "data" not in data:
            err_msg = data.get("errors", [{}])[0].get("detail", "LemonSqueezy checkout failed")
            raise RequestError(ErrorCode.SERVER_ERROR, f"LemonSqueezy initialization error: {err_msg}")

        return data["data"]["attributes"]["url"]

    def verify_webhook(self, payload: bytes, headers: Dict[str, str]) -> Dict[str, Any]:
        signature = headers.get("x-signature", headers.get("X-Signature", ""))
        if not signature or not self.webhook_secret:
            raise RequestError(ErrorCode.INVALID_ENTRY, "Missing LemonSqueezy webhook signature or secret")

        expected_sig = hmac.new(self.webhook_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise RequestError(ErrorCode.INVALID_ENTRY, "LemonSqueezy HMAC signature mismatch")

        body = json.loads(payload.decode("utf-8"))
        event_name = body.get("meta", {}).get("event_name", "")
        custom_data = body.get("meta", {}).get("custom_data", {})
        data_attrs = body.get("data", {}).get("attributes", {})

        workspace_id = custom_data.get("workspace_id")
        status = data_attrs.get("status", "active")

        # Map LemonSqueezy statuses to normalized status
        normalized_status = "active" if status in ("active", "on_trial", "paid") else "past_due"
        if event_name in ("subscription_cancelled", "subscription_expired"):
            normalized_status = "canceled"

        return {
            "event": event_name,
            "workspace_id": workspace_id,
            "status": normalized_status,
            "customer_code": str(data_attrs.get("customer_id", "")),
            "subscription_code": str(body.get("data", {}).get("id", "")),
        }
