from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_alter_user_billing_id_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='OAuthAuthorizationCode',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('client_id', models.CharField(db_index=True, max_length=128)),
                ('redirect_uri', models.CharField(max_length=2000)),
                ('scope', models.CharField(blank=True, default='', max_length=512)),
                ('code_challenge', models.CharField(max_length=128)),
                ('code_challenge_method', models.CharField(default='S256', max_length=16)),
                ('code_hash', models.CharField(max_length=64, unique=True)),
                ('expires_at', models.DateTimeField(db_index=True)),
                ('used_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='oauth_codes', to='accounts.user')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
