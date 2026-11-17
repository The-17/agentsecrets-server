"""Read a workspace plan from the resolver's billing store.

Entitlement is resolver-store-only. The control plane keeps a local mirror
(``Workspace.tier``) for display and cheap gates, but the mirror is rewritten
only by an explicit reconcile. A gate that can deny a paid feature (log
retention, seat caps) must confirm with the resolver first, or an upgrade that
lands between reconciles is treated as Free.
"""

import json
import urllib.parse
import urllib.request
from typing import Optional

from asgiref.sync import sync_to_async
from django.conf import settings

# Keep log reads snappy: a slow resolver must not stall the page. On timeout the
# caller falls back to the local mirror.
RESOLVER_TIMEOUT_S = 1.5


def _fetch_subscription(billing_id: str, bearer: str) -> Optional[dict]:
    base = getattr(settings, "RESOLVER_URL", "https://resolver.agentsecrets.tech").rstrip("/")
    query = urllib.parse.urlencode({"billing_id": billing_id})
    req = urllib.request.Request(f"{base}/v1/billing/subscription?{query}", method="GET")
    req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=RESOLVER_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _mint_bearer(user) -> str:
    from rest_framework_simplejwt.tokens import RefreshToken

    return str(RefreshToken.for_user(user).access_token)


async def bearer_for_user(user) -> str:
    """Mint a short-lived credential for a server-side resolver read.

    The resolver validates every billing read against this control plane, so
    a bare billing_id is always refused. The workspace owner is the identity
    the resolver expects for a workspace-owned account.
    """
    return await sync_to_async(_mint_bearer, thread_sensitive=False)(user)


async def resolver_plan(*, billing_id: str, user) -> Optional[dict]:
    """Return the resolver subscription payload, or None when unreachable.

    The workspace owner is minted a short-lived bearer because the resolver
    validates every billing read back against this control plane.
    """
    if getattr(settings, "TESTING", False):
        # Hermetic tests: never reach the network. Tests set the mirror tier.
        return None
    if not billing_id or billing_id.startswith("free_ws_"):
        # No payable account exists; the resolver would only echo Free.
        return None
    bearer = await bearer_for_user(user)
    return await sync_to_async(_fetch_subscription, thread_sensitive=False)(billing_id, bearer)


def plan_is_pro(payload: Optional[dict]) -> bool:
    """Pro requires both the plan and an active subscription in the store."""
    if not payload:
        return False
    return (
        str(payload.get("plan") or "").lower() == "pro"
        and str(payload.get("status") or "").lower() == "active"
    )