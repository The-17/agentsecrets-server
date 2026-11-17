# Generated for B2 autonomous rotation binding (ROTATION_PLAN Phase 2) on 2026-09-29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secrets_app', '0006_secret_rotation'),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='rotation_binding',
            field=models.JSONField(blank=True, default=dict, help_text='B2 mint params (mode/length_bytes/encoding); B3 adapter id + admin credential ref'),
        ),
    ]
