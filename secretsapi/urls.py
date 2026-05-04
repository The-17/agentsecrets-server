# Django
from django.contrib import admin
from django.urls import path, include

# Local
from .api import api

urlpatterns = [
    path("admin/", admin.site.urls),

    # Django Ninja API — all controllers auto-discovered
    path("api/", api.urls),

    # Telemetry — separate subsystem, untouched
    path("telemetry/", include("apps.telemetry.urls")),
]
