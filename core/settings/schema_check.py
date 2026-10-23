"""
Settings for the deploy-time schema gate.

`makemigrations --check` normally opens a connection to verify migration
history is consistent. At build time the database may be unreachable, and a
transient blip must not block a deploy, so this module points Django at the
`dummy` backend. Django skips its history check for that engine and the
command becomes a pure comparison of models against migration files on disk.

This module is used only by build_files.sh. It is never the runtime settings.
"""

from .base import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.dummy",
    }
}
