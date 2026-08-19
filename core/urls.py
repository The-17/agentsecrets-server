# Django
from django.contrib import admin
from django.urls import path, include

# Local
from .api import api
from apps.telemetry.api import telemetry_api

urlpatterns = [
    path("admin/", admin.site.urls),

    # Django Ninja API — all controllers auto-discovered
    # Note: Using different API instances allows us to run entirely different
    # prefix trees. We mount /api/ (standard app endpoints) and /telemetry/
    # (specifically for backward compatibility with the Go CLI).
    path("api/", api.urls),
    path("telemetry/", telemetry_api.urls),
]
