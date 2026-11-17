"""Versioned ciphertext for platform key rotation.

The production key is trapped in the hosting provider's env store and cannot be
exported, so rotation works by re-encryption: a new key arrives as
ENCRYPTION_KEY_NEXT, writes move to versioned ciphertext, and a batched sweep
converts the old rows. These tests pin the contract the sweep depends on:

- writes use the new key as soon as it exists;
- reads accept both versions for as long as both keys are configured;
- a v2 row with the new key missing fails closed instead of guessing;
- a row that cannot be decrypted is reported, never destroyed.
"""

from cryptography.fernet import Fernet
from django.test import TestCase, override_settings

from apps.common.services.encryption import EncryptionService

OLD_KEY = Fernet.generate_key().decode()
NEW_KEY = Fernet.generate_key().decode()


class VersionedEncryptionTests(TestCase):
    def test_unversioned_round_trip_when_no_next_key(self):
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            token = EncryptionService.encrypt("secret-value")
            self.assertNotIn("v2:", token)
            self.assertEqual(EncryptionService.decrypt(token), "secret-value")

    def test_writes_move_to_the_new_key_as_soon_as_it_exists(self):
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            token = EncryptionService.encrypt("secret-value")
            self.assertTrue(token.startswith("v2:"))
            self.assertEqual(EncryptionService.decrypt(token), "secret-value")

    def test_reads_accept_both_versions_during_the_window(self):
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            old_token = EncryptionService.encrypt("written-before-rotation")
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            self.assertEqual(EncryptionService.decrypt(old_token), "written-before-rotation")
            new_token = EncryptionService.encrypt("written-after-rotation")
            self.assertEqual(EncryptionService.decrypt(new_token), "written-after-rotation")

    def test_v2_row_fails_closed_when_the_new_key_is_missing(self):
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            token = EncryptionService.encrypt("v2-row")
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            with self.assertRaises(RuntimeError):
                EncryptionService.decrypt(token)

    def test_needs_rewrap_reports_old_rows_only(self):
        with override_settings(ENCRYPTION_KEY=OLD_KEY):
            old_token = EncryptionService.encrypt("old")
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            new_token = EncryptionService.encrypt("new")
            self.assertTrue(EncryptionService.needs_rewrap(old_token))
            self.assertFalse(EncryptionService.needs_rewrap(new_token))

    def test_try_decrypt_reports_instead_of_destroying(self):
        with override_settings(ENCRYPTION_KEY=OLD_KEY, ENCRYPTION_KEY_NEXT=NEW_KEY):
            self.assertIsNone(EncryptionService.try_decrypt("not-a-fernet-token"))
            token = EncryptionService.encrypt("readable")
            self.assertEqual(EncryptionService.try_decrypt(token), "readable")
