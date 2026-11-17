# Allow NULL on rotation columns so inserts from any code revision, ORM path,
# or raw SQL can never violate NOT NULL again (production 500 on credential
# creation, 2026-10-10). Keeps the 'none'/{} defaults for new objects; every
# reader already treats None exactly like the unarmed value. Also backfills
# any NULLs to the unarmed equivalents (defensive; inserts previously failed,
# so none should exist) and sets DB-level defaults as a final backstop.
from django.db import migrations, models


def backfill_unarmed(apps, schema_editor):
    Secret = apps.get_model("secrets_app", "Secret")
    Secret.objects.filter(rotation_type__isnull=True).update(rotation_type="none")
    Secret.objects.filter(rotation_binding__isnull=True).update(rotation_binding={})


class Migration(migrations.Migration):

    dependencies = [
        ('secrets_app', '0007_secret_rotation_binding'),
    ]

    operations = [
        migrations.AlterField(
            model_name='secret',
            name='rotation_type',
            field=models.CharField(
                max_length=20, default='none', null=True, blank=True, db_index=True,
                choices=[
                    ('none', 'None'),
                    ('value_client', 'Client/CI push (B1)'),
                    ('value_auto', 'Resolver-autonomous (B2)'),
                    ('value_provider', 'Provider-minted (B3)'),
                ],
            ),
        ),
        migrations.AlterField(
            model_name='secret',
            name='rotation_binding',
            field=models.JSONField(default=dict, null=True, blank=True),
        ),
        migrations.RunPython(backfill_unarmed, reverse_code=migrations.RunPython.noop),
    ]
