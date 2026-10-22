"""
Hotfix: two production issues caused by schema/code version skew.

Bug 1 — vault_version NOT NULL on INSERT
  Migration 0010 added vault_version with Django's default=0, but PostgreSQL
  only stores a Django-managed default in the ORM, not as a DB-level column
  DEFAULT. When a Lambda deployment that predates 0010 INSERTs a User row it
  omits the column entirely; the DB sees NULL and rejects it.
  Fix: set an explicit DB-level DEFAULT 0 on the column so every INSERT path
  (new code or old code) produces a valid row.

Bug 2 — ForeignKeyViolation on User delete via admin
  Migration 0012 created OpaqueLoginChallenge with on_delete=CASCADE in the
  Django model, but the underlying Postgres FK constraint has no ON DELETE
  CASCADE clause — Django's collector handles cascade in Python. If the
  deployed Lambda snapshot does not include OpaqueLoginChallenge in its model
  registry the Python collector never sees the rows, the FK is not satisfied,
  and the database raises a ForeignKeyViolation.
  Fix: alter the FK constraint to add ON DELETE CASCADE at DB level so the
  database enforces it regardless of which code revision is deployed.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0012_opaque_enrollment"),
    ]

    operations = [
        # Bug 1 fix: materialise the Django default as a real DB-level DEFAULT.
        migrations.RunSQL(
            sql="""
                ALTER TABLE accounts_user
                    ALTER COLUMN vault_version SET DEFAULT 0;
            """,
            reverse_sql="""
                ALTER TABLE accounts_user
                    ALTER COLUMN vault_version DROP DEFAULT;
            """,
        ),

        # Bug 2 fix: replace the FK constraint with one that has ON DELETE CASCADE.
        migrations.RunSQL(
            sql="""
                ALTER TABLE accounts_opaqueloginchallenge
                    DROP CONSTRAINT IF EXISTS accounts_opaquelogin_user_id_a4bf9a9a_fk_accounts_,
                    ADD CONSTRAINT accounts_opaquelogin_user_id_a4bf9a9a_fk_accounts_
                        FOREIGN KEY (user_id)
                        REFERENCES accounts_user(id)
                        ON DELETE CASCADE
                        DEFERRABLE INITIALLY DEFERRED;
            """,
            reverse_sql="""
                ALTER TABLE accounts_opaqueloginchallenge
                    DROP CONSTRAINT IF EXISTS accounts_opaquelogin_user_id_a4bf9a9a_fk_accounts_,
                    ADD CONSTRAINT accounts_opaquelogin_user_id_a4bf9a9a_fk_accounts_
                        FOREIGN KEY (user_id)
                        REFERENCES accounts_user(id)
                        DEFERRABLE INITIALLY DEFERRED;
            """,
        ),
    ]
