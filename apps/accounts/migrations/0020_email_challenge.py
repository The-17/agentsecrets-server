import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0019_social_identity_link"),
    ]

    operations = [
        migrations.AddField(
            model_name="onetimepassword",
            name="purpose",
            field=models.CharField(
                choices=[("verify_email", "Verify Email"), ("email_change", "Email Change")],
                default="email_change",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="onetimepassword",
            name="email",
            field=models.EmailField(blank=True, default="", max_length=254),
        ),
        migrations.AddField(
            model_name="onetimepassword",
            name="created_at",
            field=models.DateTimeField(default=django.utils.timezone.now, editable=False),
        ),
        migrations.AddField(
            model_name="onetimepassword",
            name="expires_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="onetimepassword",
            name="attempts",
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
