from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("workspaces", "0016_agenttoken_rotation"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditlogentry",
            name="correlation_id",
            field=models.CharField(blank=True, db_index=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="forensicauditlogentry",
            name="correlation_id",
            field=models.CharField(blank=True, db_index=True, default="", max_length=64),
        ),
    ]
