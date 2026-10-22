"""
Hotfix 0014: Add ON DELETE CASCADE to all remaining FKs referencing accounts_user.

Migration 0013 fixed accounts_opaqueloginchallenge. This migration fixes the
remaining three tables that have the same schema/code-version-skew problem:
  - accounts_vaultrecoverychallenge  (error seen 2026-10-22 10:34)
  - accounts_oauthauthorizationcode
  - accounts_onetimepassword

Each RunSQL block drops the existing FK by name (IF EXISTS for safety) then
recreates it with ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED, matching
the style used in 0013 for the opaque challenge table.

Constraint names taken directly from live Postgres error messages and
pg_constraint introspection; they match Django's truncated naming formula.
"""

from django.db import migrations


_CASCADE_SUFFIX = "ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED"
_PLAIN_SUFFIX = "DEFERRABLE INITIALLY DEFERRED"


def _alter_fk(table, col, ref_table, ref_col, old_constraint, new_constraint):
    """Return (forward_sql, reverse_sql) pair for a CASCADE FK swap."""
    forward = f"""
        ALTER TABLE {table}
            DROP CONSTRAINT IF EXISTS {old_constraint},
            ADD CONSTRAINT {new_constraint}
                FOREIGN KEY ({col})
                REFERENCES {ref_table}({ref_col})
                {_CASCADE_SUFFIX};
    """
    reverse = f"""
        ALTER TABLE {table}
            DROP CONSTRAINT IF EXISTS {new_constraint},
            ADD CONSTRAINT {old_constraint}
                FOREIGN KEY ({col})
                REFERENCES {ref_table}({ref_col})
                {_PLAIN_SUFFIX};
    """
    return forward, reverse


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0013_hotfix_vault_version_default_and_opaque_fk_cascade"),
    ]

    operations = [
        # VaultRecoveryChallenge — confirmed constraint name from 2026-10-22 error log
        migrations.RunSQL(
            *_alter_fk(
                table="accounts_vaultrecoverychallenge",
                col="user_id",
                ref_table="accounts_user",
                ref_col="id",
                old_constraint="accounts_vaultrecove_user_id_b4e2e914_fk_accounts_",
                new_constraint="accounts_vaultrecove_user_id_b4e2e914_fk_accounts_",
            )
        ),

        # OAuthAuthorizationCode — drop whatever Django named it, recreate with CASCADE.
        # Uses a DO block to find the constraint name dynamically rather than
        # hardcoding a potentially wrong hash, then recreates with a stable name.
        migrations.RunSQL(
            sql="""
                DO $$
                DECLARE
                    _con text;
                BEGIN
                    SELECT conname INTO _con
                    FROM pg_constraint
                    WHERE conrelid = 'accounts_oauthauthorizationcode'::regclass
                      AND confrelid = 'accounts_user'::regclass
                      AND contype = 'f';

                    IF _con IS NOT NULL THEN
                        EXECUTE format(
                            'ALTER TABLE accounts_oauthauthorizationcode DROP CONSTRAINT %I', _con
                        );
                    END IF;

                    ALTER TABLE accounts_oauthauthorizationcode
                        ADD CONSTRAINT accounts_oauthauth_user_id_cascade_fk
                            FOREIGN KEY (user_id)
                            REFERENCES accounts_user(id)
                            ON DELETE CASCADE
                            DEFERRABLE INITIALLY DEFERRED;
                END
                $$;
            """,
            reverse_sql="""
                DO $$
                BEGIN
                    ALTER TABLE accounts_oauthauthorizationcode
                        DROP CONSTRAINT IF EXISTS accounts_oauthauth_user_id_cascade_fk,
                        ADD CONSTRAINT accounts_oauthauth_user_id_cascade_fk
                            FOREIGN KEY (user_id)
                            REFERENCES accounts_user(id)
                            DEFERRABLE INITIALLY DEFERRED;
                END
                $$;
            """,
        ),

        # OneTimePassword — same dynamic approach
        migrations.RunSQL(
            sql="""
                DO $$
                DECLARE
                    _con text;
                BEGIN
                    SELECT conname INTO _con
                    FROM pg_constraint
                    WHERE conrelid = 'accounts_onetimepassword'::regclass
                      AND confrelid = 'accounts_user'::regclass
                      AND contype = 'f';

                    IF _con IS NOT NULL THEN
                        EXECUTE format(
                            'ALTER TABLE accounts_onetimepassword DROP CONSTRAINT %I', _con
                        );
                    END IF;

                    ALTER TABLE accounts_onetimepassword
                        ADD CONSTRAINT accounts_onetimepw_user_id_cascade_fk
                            FOREIGN KEY (user_id)
                            REFERENCES accounts_user(id)
                            ON DELETE CASCADE
                            DEFERRABLE INITIALLY DEFERRED;
                END
                $$;
            """,
            reverse_sql="""
                DO $$
                BEGIN
                    ALTER TABLE accounts_onetimepassword
                        DROP CONSTRAINT IF EXISTS accounts_onetimepw_user_id_cascade_fk,
                        ADD CONSTRAINT accounts_onetimepw_user_id_cascade_fk
                            FOREIGN KEY (user_id)
                            REFERENCES accounts_user(id)
                            DEFERRABLE INITIALLY DEFERRED;
                END
                $$;
            """,
        ),
    ]
