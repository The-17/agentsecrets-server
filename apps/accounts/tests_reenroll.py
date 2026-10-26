"""Recovery must leave an account able to re-enroll.

Recovery clears the OPAQUE record and restores a password (commit 62e3099), so
the account is temporarily password-only. The CLI then re-enrolls through the
same register/start + register/finish endpoints as a first-time enrollment,
gated on recovery_confirmed. These tests pin the server side of that loop: the
storage boundary recovery hands control back to fails closed, and a recovered
account gets exactly the same atomic record-plus-hash-removal as a fresh
enrollment.
"""

import inspect
from unittest.mock import patch

from asgiref.sync import async_to_sync
from django.test import TestCase

from apps.accounts.models import User
from apps.accounts.opaque_services import OpaqueService, SidecarError
from apps.common.exceptions import OpaqueUnavailableError


class ReenrollAfterRecoveryTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="reenroll@example.com",
            first_name="Re",
            last_name="Enroll",
            password="correct-horse-battery",
            terms_agreement=True,
        )
        # The post-recovery state: record cleared, password restored.
        self.user.opaque_record = None
        self.user.opaque_registered_at = None
        self.user.save()

    def _failing_sidecar(self):
        class FailingSidecar:
            def register_finish(self, *_args, **_kwargs):
                raise SidecarError("sidecar unavailable")

        return FailingSidecar()

    def test_failed_sidecar_leaves_the_recovered_account_untouched(self):
        # Fail-closed: if the sidecar cannot finish the re-enrollment, the
        # account must keep its restored password and stay record-free, never
        # stranded between the two auth methods.
        #
        # reenroll_after_recovery is async, so it must be driven to completion
        # here. Calling it bare would return a coroutine and assert nothing.
        failing = self._failing_sidecar()
        service = OpaqueService()
        with patch.object(type(service), "sidecar", new=property(lambda _self: failing)):
            with self.assertRaises(OpaqueUnavailableError):
                async_to_sync(service.reenroll_after_recovery)(
                    user=self.user,
                    cred_id="reenroll@example.com",
                    reg_record=b"record-blob",
                )

        self.user.refresh_from_db()
        self.assertIsNone(self.user.opaque_record)
        self.assertIsNone(self.user.opaque_registered_at)
        self.assertTrue(self.user.has_usable_password())

    def test_reenroll_uses_the_same_storage_path_as_first_enrollment(self):
        # Both flows delegate to _store_record, so a recovered account gets the
        # same atomic record-plus-hash-removal as a fresh one. That symmetry is
        # why no separate re-enroll endpoint exists or needs to.
        reenroll_source = inspect.getsource(OpaqueService.reenroll_after_recovery)
        finish_source = inspect.getsource(OpaqueService.register_user_finish_async)
        self.assertIn("_store_record", reenroll_source)
        self.assertIn("_store_record", finish_source)
