"""Tests for the server-side resolver billing read."""

from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from apps.workspaces.billing_source import _fetch_subscription


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return b'{"plan":"pro","status":"active"}'


@override_settings(RESOLVER_URL="https://resolver.example")
class ResolverBillingFetchTest(SimpleTestCase):
    def test_fetch_subscription_sends_the_bearer_credential(self):
        with patch(
            "apps.workspaces.billing_source.urllib.request.urlopen",
            return_value=FakeResponse(),
        ) as fetch:
            payload = _fetch_subscription("bill_1", "owner-token")
            request = fetch.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer owner-token")
            self.assertEqual(payload["plan"], "pro")
