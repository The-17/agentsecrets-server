#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from decouple import config


def main():
    """Run administrative tasks."""
    settings_val = config("SETTINGS", default="dev")
    if settings_val.startswith("core.settings."):
        settings_module = settings_val
    elif settings_val.startswith("secretsapi.settings."):
        settings_module = settings_val.replace("secretsapi.settings.", "core.settings.")
    else:
        settings_module = f"core.settings.{settings_val}"

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', settings_module)
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
