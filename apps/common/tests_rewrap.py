"""Sweep tests: the batched re-encryption used during platform key rotation.

These pin what the operator loop depends on when it drains the trapped
production key:

- rows move from the original key to versioned ciphertext and still decrypt;
- rerunning the sweep over already-versioned rows changes nothing;
- a row the old key cannot read is reported by primary key, never destroyed;
- the endpoint refuses to run without a configured operator token, and
  especially refuses to run when rotation is not active at all;
- cursors make progress across batches and report exhaustion honestly.
"""

from cryptography.fernet import Fernet
from django.test import Client, TestCase, override_settings

from apps.accounts.models import User
from apps.common.services.encryption import EncryptionService
from apps.common.services.rewrap import check_rotation_token, rewrap_batch
from apps.secrets_app.models import Project, Secret

OLD_KEY = Fernet.generate_key().decode()
NEW_KEY = Fernet.generate_key().decode()
PASSPHRASE = "old row content " + str(Fernet.generate_key())
OPERATOR_TOKEN = "operator-token-0123456789abcdef"


def _make_user(i: int) -> User:
    return User.objects.create_user(
        email=f"sweep{i}@example.com",
        password="pw",
        first_name="Sweep",
        last_name=str(i),
    )


def _workspace(owner: User):
    from apps.workspaces.models import Workspace

    return Workspace.objects.create(name="w", owner=owner, type="personal")


def _seed_plaintext(i: int) -> str:
    return f"plaintext-for-row-{i}"


class SweepTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = _make_user(0)
        self.project = Project.objects.create(
            workspace=_workspace(self.owner), name="p0"
        )

    def _seed_secret_old_format(self, i: int) -> Secret:
        """Seed a row exactly as it exists today: unversioned, on the old key."""
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            value = EncryptionService.encrypt(_seed_plaintext(i))
        return Secret.objects.create(project=self.project, key=f"K{i}", value=value)

    def test_refuses_to_sweep_when_rotation_is_inactive(self):
        self._seed_secret_old_format(1)
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            with self.assertRaises(RuntimeError):
                rewrap_batch()

    def test_rows_move_to_versioned_ciphertext_and_decrypt(self):
        secret = self._seed_secret_old_format(1)
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            result = rewrap_batch()
            self.assertTrue(result["finished"])
            self.assertEqual(result["secrets"]["rewrapped"], 1)
            secret.refresh_from_db()
            self.assertTrue(secret.value.startswith("v2:"))
            plain = Fernet(NEW_KEY.encode()).decrypt(secret.value[3:].encode())
            self.assertEqual(plain.decode(), _seed_plaintext(1))

    def test_second_pass_is_idempotent(self):
        secret = self._seed_secret_old_format(1)
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            rewrap_batch()
            secret.refresh_from_db()
            after_first = secret.value
            result = rewrap_batch()
            self.assertEqual(result["secrets"]["rewrapped"], 0)
            self.assertEqual(result["secrets"]["remaining"], 0)
            secret.refresh_from_db()
            self.assertEqual(secret.value, after_first)

    def test_undecryptable_rows_are_reported_and_untouched(self):
        secret = self._seed_secret_old_format(1)
        secret.value = "not-a-fernet-token"
        secret.save(update_fields=["value"])
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            result = rewrap_batch()
            self.assertEqual(result["secrets"]["skipped"], [secret.pk])
            self.assertEqual(result["secrets"]["rewrapped"], 0)
            secret.refresh_from_db()
            self.assertEqual(secret.value, "not-a-fernet-token")

    def test_key_salts_rewrap_and_nulls_are_skipped(self):
        user_with_salt = _make_user(1)
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            user_with_salt.key_salt = EncryptionService.encrypt("salt-value")
        user_with_salt.save(update_fields=["key_salt"])
        user_without_salt = _make_user(2)  # key_salt stays null

        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            result = rewrap_batch()
            self.assertEqual(result["key_salts"]["rewrapped"], 1)
            self.assertEqual(result["key_salts"]["remaining"], 0)
            user_with_salt.refresh_from_db()
            self.assertTrue(user_with_salt.key_salt.startswith("v2:"))
            plain = Fernet(NEW_KEY.encode()).decrypt(
                user_with_salt.key_salt[3:].encode()
            )
            self.assertEqual(plain.decode(), "salt-value")
            user_without_salt.refresh_from_db()
            self.assertIsNone(user_without_salt.key_salt)

    def test_cursors_advance_and_report_exhaustion(self):
        for i in range(1, 3):
            self._seed_secret_old_format(i)
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            first = rewrap_batch(limit=1)
            self.assertFalse(first["secrets"]["done"])
            self.assertEqual(first["secrets"]["rewrapped"], 1)
            second = rewrap_batch(
                secret_cursor=first["secrets"]["cursor"], limit=1
            )
            self.assertTrue(second["finished"])
            self.assertEqual(second["secrets"]["rewrapped"], 1)

    def test_operator_token_fails_closed_when_unset(self):
        with override_settings(ROTATION_TOKEN=""):
            self.assertFalse(check_rotation_token(OPERATOR_TOKEN))
            self.assertFalse(check_rotation_token(""))

    def test_operator_token_matches_constant_time(self):
        with override_settings(ROTATION_TOKEN=OPERATOR_TOKEN):
            self.assertTrue(check_rotation_token(OPERATOR_TOKEN))
            self.assertFalse(check_rotation_token("wrong"))
            self.assertFalse(check_rotation_token(""))

    def test_endpoint_guards_before_sweeping(self):
        self._seed_secret_old_format(1)
        url = "/api/admin/rotation/rewrap/"

        # No operator token configured: everything is refused, even "correct".
        with override_settings(ROTATION_TOKEN="", ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            response = self.client.post(
                url,
                {"secret_cursor": 0, "salt_cursor": 0},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {OPERATOR_TOKEN}",
            )
            self.assertEqual(response.status_code, 403)

        # Correct token, but rotation inactive: 409, rows untouched.
        with override_settings(ROTATION_TOKEN=OPERATOR_TOKEN, ENCRYPTION_KEY=OLD_KEY):
            response = self.client.post(
                url,
                {"secret_cursor": 0, "salt_cursor": 0},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {OPERATOR_TOKEN}",
            )
            self.assertEqual(response.status_code, 409)

        # Wrong token while rotation is active: 403, rows untouched.
        with override_settings(
            ROTATION_TOKEN=OPERATOR_TOKEN,
            ENCRYPTION_KEY=OLD_KEY,
            ENCRYPTION_KEY_NEXT=NEW_KEY,
        ):
            response = self.client.post(
                url,
                {"secret_cursor": 0, "salt_cursor": 0},
                content_type="application/json",
                HTTP_AUTHORIZATION="Bearer something-else",
            )
            self.assertEqual(response.status_code, 403)

    def test_endpoint_sweeps_with_valid_token(self):
        secret = self._seed_secret_old_format(1)
        with override_settings(
            ROTATION_TOKEN=OPERATOR_TOKEN,
            ENCRYPTION_KEY=OLD_KEY,
            ENCRYPTION_KEY_NEXT=NEW_KEY,
        ):
            response = self.client.post(
                "/api/admin/rotation/rewrap/",
                {"secret_cursor": 0, "salt_cursor": 0},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {OPERATOR_TOKEN}",
            )
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["data"]["finished"])
            secret.refresh_from_db()
            self.assertTrue(secret.value.startswith("v2:"))
