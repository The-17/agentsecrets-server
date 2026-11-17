"""The account-probe endpoint: what it reveals, and what it refuses.

The auth UI asks whether an email is registered so it can pick the next step.
That is enumeration by design, so these tests pin the two things that keep it
from becoming a directory: the answer is a bare boolean, and it is paced per
caller.
"""

from django.test import TestCase

from apps.accounts.models import User
from apps.accounts.probe_limit import MAX_PROBES_PER_WINDOW, _ip_key


class AccountProbeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="probe@example.com",
            first_name="Probe",
            last_name="User",
            password="correct-horse-battery",
            terms_agreement=True,
        )

    def probe(self, email, ip="203.0.113.7"):
        return self.client.post(
            "/api/users/probe/",
            data={"email": email},
            content_type="application/json",
            HTTP_X_FORWARDED_FOR=ip,
        )

    def test_existing_account_reports_true(self):
        response = self.probe("probe@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["data"]["exists"])

    def test_unknown_account_reports_false_not_an_error(self):
        # A 404 here would be a different signal from exists=false, and the
        # point of the boolean is that there is only one way to read it.
        response = self.probe("nobody@example.com")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["data"]["exists"])

    def test_response_does_not_name_existence(self):
        response = self.probe("probe@example.com")
        body = response.json()
        self.assertNotIn("message", body.get("data") or {})
        # The envelope message must stay neutral for both outcomes.
        self.assertEqual(body["message"], self.probe("nobody@example.com").json()["message"])

    def test_probe_is_rate_limited_per_caller(self):
        for _ in range(MAX_PROBES_PER_WINDOW):
            self.assertEqual(self.probe("probe@example.com").status_code, 200)

        blocked = self.probe("probe@example.com")
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.json()["code"], "rate_limited")

    def test_rate_limit_is_per_ip_not_global(self):
        for _ in range(MAX_PROBES_PER_WINDOW):
            self.probe("probe@example.com", ip="203.0.113.7")

        # A different caller is unaffected.
        self.assertEqual(self.probe("probe@example.com", ip="198.51.100.9").status_code, 200)

    def test_probe_does_not_store_raw_addresses(self):
        from apps.accounts.models import AccountProbe

        self.probe("probe@example.com", ip="203.0.113.7")
        stored = list(AccountProbe.objects.values_list("ip_hash", flat=True))
        self.assertEqual(len(stored), 1)
        self.assertNotIn("203.0.113.7", stored[0])
        self.assertEqual(stored[0], _ip_key("203.0.113.7"))
