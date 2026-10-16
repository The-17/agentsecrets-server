# Django
from django.contrib import admin
from django.urls import path, include

# Local
from .api import api
from apps.accounts.oauth_views import (
    oauth_authorize,
    oauth_discovery,
    oauth_token,
)
from apps.telemetry.api import telemetry_api

urlpatterns = [
    path("admin/", admin.site.urls),

    # OAuth 2.1 Authorization Code + PKCE for headless agent login
    # (MCP bridge `auth_login`). Mounted at SITE ROOT — not under /api/ —
    # because clients trim `/api` from the control-plane base before
    # discovery. Plain Django views: the browser consent flow needs
    # sessions + CSRF, which the token endpoint exempts (PKCE-bound codes).
    path(
        ".well-known/oauth-authorization-server",
        oauth_discovery,
        name="oauth-discovery",
    ),
    path("oauth/authorize", oauth_authorize, name="oauth-authorize"),
    path("oauth/token", oauth_token, name="oauth-token"),

    # Django Ninja API — all controllers auto-discovered
    # Note: Using different API instances allows us to run entirely different
    # prefix trees. We mount /api/ (standard app endpoints) and /telemetry/
    # (specifically for backward compatibility with the Go CLI).
    path("api/", api.urls),
    path("telemetry/", telemetry_api.urls),
]
