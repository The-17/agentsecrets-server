from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0009_oauth_authorization_code"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="vault",
            field=models.JSONField(
                blank=True,
                help_text="Opaque client-side vault record: wrapped VK envelopes and proof",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="vault_version",
            field=models.PositiveIntegerField(
                default=0,
                help_text="Optimistic concurrency version for the vault record",
            ),
        ),
    ]
