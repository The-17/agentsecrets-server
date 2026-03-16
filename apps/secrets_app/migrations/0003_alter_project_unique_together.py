# Fixed migration: 0002 removed the 'owner' field but didn't clear the
# (owner, name) unique_together first. Django's AlterUniqueTogether needs
# to drop the old constraint before creating the new one, and it looks up
# the old fields by name — crashing if 'owner' is already gone.
# We clear the stale constraint first, then set the correct one.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('secrets_app', '0002_alter_secret_options_and_more'),
        ('workspaces', '0001_initial'),
    ]

    operations = [
        # First clear any stale unique_together from the old (owner, name) pair
        migrations.AlterUniqueTogether(
            name='project',
            unique_together=set(),
        ),
        # Now set the correct constraint using the current fields
        migrations.AlterUniqueTogether(
            name='project',
            unique_together={('workspace', 'name')},
        ),
    ]
