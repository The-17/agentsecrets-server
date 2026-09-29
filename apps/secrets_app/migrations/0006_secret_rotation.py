# Generated for B1 client-push value rotation (ROTATION_PLAN Phase 1) on 2026-09-29

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('secrets_app', '0005_secret_policy'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='secret',
            name='rotation_type',
            field=models.CharField(choices=[('none', 'None'), ('value_client', 'Client/CI push (B1)'), ('value_auto', 'Resolver-autonomous (B2)'), ('value_provider', 'Provider-minted (B3)')], db_index=True, default='none', help_text='Rotation class; arming is desired-state only, execution is Pro-gated in the resolver (HR-M3)', max_length=20),
        ),
        migrations.AddField(
            model_name='secret',
            name='rotation_period',
            field=models.DurationField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='secret',
            name='rotation_overlap',
            field=models.DurationField(blank=True, help_text='Routine-rotation grace window; null means the 24h default', null=True),
        ),
        migrations.AddField(
            model_name='secret',
            name='next_rotation_at',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.CreateModel(
            name='SecretVersion',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('ciphertext', models.TextField()),
                ('staging_label', models.CharField(choices=[('pending', 'Pending'), ('current', 'Current'), ('previous', 'Previous')], db_index=True, max_length=20)),
                ('rotation_reason', models.CharField(choices=[('routine', 'Routine'), ('compromise', 'Compromise')], default='routine', max_length=20)),
                ('rotation_id', models.CharField(blank=True, db_index=True, help_text='Idempotency key of the rotation cycle that created this version (HR-H4)', max_length=100, null=True)),
                ('provider_binding', models.JSONField(blank=True, default=dict, help_text="B1: {'mode': 'out-of-band'}; B2/B3: adapter id + admin credential ref")),
                ('overlap_until', models.DateTimeField(blank=True, help_text='Previous row becomes reapable after this time (routine only)', null=True)),
                ('revoked_at', models.DateTimeField(blank=True, help_text='Poisoned (compromise): never a rollback target, never promotable (HR-H3)', null=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_secret_versions', to=settings.AUTH_USER_MODEL)),
                ('secret', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='versions', to='secrets_app.secret')),
            ],
            options={
                'db_table': 'secret_versions',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddConstraint(
            model_name='secretversion',
            constraint=models.UniqueConstraint(condition=models.Q(('staging_label', 'pending')), fields=('secret',), name='uniq_pending_version_per_secret'),
        ),
        migrations.AddConstraint(
            model_name='secretversion',
            constraint=models.UniqueConstraint(condition=models.Q(('staging_label', 'current')), fields=('secret',), name='uniq_current_version_per_secret'),
        ),
        migrations.AddIndex(
            model_name='secretversion',
            index=models.Index(fields=['secret', 'staging_label'], name='secret_vers_secret__2f50d0_idx'),
        ),
        migrations.AddIndex(
            model_name='secretversion',
            index=models.Index(fields=['secret', '-created_at'], name='secret_vers_secret__483018_idx'),
        ),
    ]
