"""
Hotfix 0015: DB-level defaults for every remaining NOT NULL column on
accounts_user that only had a Django-managed default.

Same bug class as 0013's vault_version fix. Django stores `default=` in the
ORM, not in Postgres. Any INSERT path that does not come from the current
model code (an older Lambda snapshot, a raw SQL migration, a psql repair)
omits the column, and Postgres rejects the whole row with a NOT NULL
violation. That is exactly the /api/auth/register/ 500 seen in production.

0013 fixed vault_version. This migration closes the rest of the class:
auth_provider and the five boolean flags.

`ALTER COLUMN ... SET DEFAULT` is a catalog-only change. It does not rewrite
the table and does not lock rows, so it is safe to run on the live database.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0014_hotfix_cascade_remaining_user_fks"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                ALTER TABLE accounts_user
                    ALTER COLUMN auth_provider SET DEFAULT 'email',
                    ALTER COLUMN is_active SET DEFAULT true,
                    ALTER COLUMN is_staff SET DEFAULT false,
                    ALTER COLUMN is_superuser SET DEFAULT false,
                    ALTER COLUMN is_email_verified SET DEFAULT false,
                    ALTER COLUMN terms_agreement SET DEFAULT false;
            """,
            reverse_sql="""
                ALTER TABLE accounts_user
                    ALTER COLUMN auth_provider DROP DEFAULT,
                    ALTER COLUMN is_active DROP DEFAULT,
                    ALTER COLUMN is_staff DROP DEFAULT,
                    ALTER COLUMN is_superuser DROP DEFAULT,
                    ALTER COLUMN is_email_verified DROP DEFAULT,
                    ALTER COLUMN terms_agreement DROP DEFAULT;
            """,
        ),
    ]
