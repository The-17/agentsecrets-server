# Generated for Axis A token rotation (ROTATION_PLAN Phase 1) on 2026-09-28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('workspaces', '0015_workspace_tier'),
    ]

    operations = [
        migrations.AddField(
            model_name='agenttoken',
            name='rotation_family_id',
            field=models.CharField(blank=True, db_index=True, help_text='Root token id of this rotation family; assigned on first rotation', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='supersedes',
            field=models.CharField(blank=True, help_text='Token id this token directly succeeds (plain id reference, never a raw token)', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='superseded_by',
            field=models.CharField(blank=True, help_text='Token id that directly succeeds this token', max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='rotation_period',
            field=models.DurationField(blank=True, help_text='Automated cadence; arming is desired-state only, execution is Pro-gated in the resolver (HR-M3)', null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='rotation_overlap',
            field=models.DurationField(blank=True, help_text='Routine-rotation grace window; null means the 24h default', null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='next_rotation_at',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='overlap_until',
            field=models.DateTimeField(blank=True, help_text='Superseded predecessor stays valid until this time (routine rotation only; compromise revokes immediately)', null=True),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='rotation_state',
            field=models.CharField(choices=[('active', 'Active'), ('superseded', 'Superseded'), ('revoked', 'Revoked')], db_index=True, default='active', help_text='active | superseded (in overlap) | revoked (explicit or compromise-poisoned)', max_length=20),
        ),
        migrations.AddField(
            model_name='agenttoken',
            name='rotation_id',
            field=models.CharField(blank=True, db_index=True, help_text='Idempotency key of the rotation cycle that minted this token (HR-H4)', max_length=100, null=True),
        ),
    ]
