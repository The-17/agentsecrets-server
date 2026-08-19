import os
from decouple import config
from django.core.asgi import get_asgi_application

settings_val = config("SETTINGS", default="dev")
if settings_val.startswith("core.settings."):
    settings_module = settings_val
elif settings_val.startswith("secretsapi.settings."):
    settings_module = settings_val.replace("secretsapi.settings.", "core.settings.")
else:
    settings_module = f"core.settings.{settings_val}"

os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)

application = get_asgi_application()
