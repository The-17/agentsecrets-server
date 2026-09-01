import ulid
from django.db import migrations, models

def generate_unique_billing_ids(apps, schema_editor):
    User = apps.get_model("accounts", "User")
    for user in User.objects.all():
        if not user.billing_id:
            user.billing_id = f"bill_{str(ulid.ULID())}"
            user.save(update_fields=["billing_id"])

class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0006_remove_user_accounts_us_last_ac_088c77_idx_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="billing_id",
            field=models.CharField(
                blank=True,
                help_text="Mandatory AgentSecrets Cloud billing & entitlement identifier",
                max_length=64,
                null=True,
            ),
        ),
        migrations.RunPython(
            generate_unique_billing_ids,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name="user",
            name="billing_id",
            field=models.CharField(
                blank=True,
                help_text="Mandatory AgentSecrets Cloud billing & entitlement identifier",
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
    ]
