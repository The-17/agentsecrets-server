import time
import logging
from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from apps.accounts.models import User
from apps.accounts.services import AccountService

logger = logging.getLogger("django.access")


class AuditLogMiddleware:
    """
    Middleware to log request status, method, path, and execution duration
    without leaking user PII (emails/tokens/IPs) to console outputs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        start_time = time.time()
        response = self.get_response(request)
        duration = time.time() - start_time

        # Mask identity to prevent PII exposure in console/open-source logs
        is_authenticated = False
        if hasattr(request, "auth") and request.auth:
            is_authenticated = True
        elif hasattr(request, "user") and request.user.is_authenticated:
            is_authenticated = True

        identity_label = "Authenticated" if is_authenticated else "Anonymous"
        log_message = (
            f"[ACCESS] {response.status_code} {request.method} {request.path} "
            f"({identity_label}) [{duration:.3f}s]"
        )

        if response.status_code >= 500:
            logger.error(log_message)
        elif response.status_code >= 400:
            logger.warning(log_message)
        else:
            logger.debug(log_message)

        return response


def get_user_from_request(request):
    user = None
    if hasattr(request, "auth") and request.auth:
        if isinstance(request.auth, User):
            user = request.auth
    if not user and hasattr(request, "user") and request.user and request.user.is_authenticated:
        if isinstance(request.user, User):
            user = request.user
    return user


class ActivityTrackingMiddleware:
    """
    Middleware to capture and stamp active users.
    Throttled to 15-minute intervals inside AccountService.
    Supports both async (ASGI) and sync (WSGI) request cycles.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        if iscoroutinefunction(self.get_response):
            markcoroutinefunction(self)

    async def __acall__(self, request):
        response = await self.get_response(request)
        if response.status_code < 400:
            user = get_user_from_request(request)
            if user:
                await AccountService.stamp_user_activity(user=user)
        return response

    def __call__(self, request):
        response = self.get_response(request)
        if response.status_code < 400:
            user = get_user_from_request(request)
            if user:
                AccountService.stamp_user_activity_sync(user=user)
        return response


class SecurityHeadersMiddleware:
    """
    Injects production security headers on all responses:
    - HSTS: Forces HTTPS for 1 year with subdomains and preload.
    - X-Content-Type-Options: Prevents MIME-type sniffing attacks.
    - X-Frame-Options: Blocks clickjacking via iframe embedding.
    - Referrer-Policy: Limits referrer leakage to origin only on cross-origin.
    - Cache-Control: Prevents proxy/CDN caching of sensitive auth responses.

    Auth-sensitive routes (/api/auth/, /auth/) additionally receive
    no-store directives to prevent token caching in intermediate proxies.
    """

    # Paths where responses must never be cached (tokens, credentials)
    SENSITIVE_PREFIXES = ("/api/auth/", "/auth/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # Prevent intermediate proxies from caching auth tokens
        if any(request.path.startswith(p) for p in self.SENSITIVE_PREFIXES):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate"

        return response
