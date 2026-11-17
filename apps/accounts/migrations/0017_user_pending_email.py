# Generated manually to add the pending_email field for the email-change flow.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0016_accountprobe'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='pending_email',
            field=models.EmailField(blank=True, null=True, verbose_name='Pending Email'),
        ),
    ]
