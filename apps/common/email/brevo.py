"""Brevo transactional email client.

Delivery uses Brevo's HTTPS API (``POST /v3/smtp/email`` with an ``api-key``
header). It is not an SMTP relay: no host, port, or SMTP credentials are read.
The endpoint name is Brevo's own naming for transactional mail.

When ``BREVO_API_KEY`` is set, ``send`` posts to that API. When it is unset,
``send`` logs locally and returns ``False`` so callers can hard-fail with a
clear "email delivery not configured" message rather than silently dropping the
mail. Call sites live in ``apps.accounts.email_challenges``.
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
