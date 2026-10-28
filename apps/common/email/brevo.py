"""Brevo transactional email client (groundwork).

This is the delivery channel for flows that must prove control of an address
(email change, future real email verification). It is intentionally NOT yet
wired into any flow except as a no-op fallback.

When ``BREVO_API_KEY`` is set, ``send`` posts to Brevo's SMTP API. When it is
unset, ``send`` logs locally and returns ``False`` so callers can hard-fail with
a clear "email delivery not configured" message rather than silently dropping
the mail. Once the key is set on a host, the only remaining wiring is the call
site (today: ``AccountService.request_email_change``).
"""
import logging

import requests
from django.conf import settings

logger = logging.getLogger("apps.common.email.brevo")

BREVO_SMTP_URL = "https://api.brevo.com/v3/smtp/email"


def send(*, to: str, subject: str, text: str, html: str | None = None) -> bool:
    """Send a transactional email via Brevo.

    Returns True if Brevo accepted the request, False if delivery is not
    configured or the request failed. The caller decides whether a False
    result should block the flow.
    """
    api_key = getattr(settings, "BREVO_API_KEY", "")
    sender = getattr(settings, "BREVO_SENDER", "")

    if not api_key:
        logger.info(
            "BREVO_API_KEY unset; dev no-op send to=%s subject=%s", to, subject
        )
        return False

    payload = {
        "sender": {"email": sender},
        "to": [{"email": to}],
        "subject": subject,
        "textContent": text,
    }
    if html:
        payload["htmlContent"] = html

    try:
        resp = requests.post(
            BREVO_SMTP_URL,
            json=payload,
            headers={"api-key": api_key, "Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - surfaced to caller as False
        logger.exception("Brevo send failed: %s", exc)
        return False

    return True
