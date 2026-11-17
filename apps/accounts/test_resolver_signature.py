import base64
import hashlib
import time
from unittest.mock import patch

from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, override_settings
from nacl.signing import SigningKey

from apps.accounts.auth import ResolverSignatureAuth


OLD_KEY = SigningKey.generate()
NEW_KEY = SigningKey.generate()
BUNDLE_SPEC = f"primary:{bytes(OLD_KEY.verify_key).hex()},next:{bytes(NEW_KEY.verify_key).hex()}"


def _signed_request(factory, *, path, signing_key, key_id, body=b""):
    timestamp = str(int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    payload = "\n".join([timestamp, "GET", path, body_hash])
    signature = signing_key.sign(payload.encode()).signature
    request = factory.get(path)
    request.META.update(
        {
            "HTTP_X_RESOLVER_KEY_ID": key_id,
            "HTTP_X_RESOLVER_TIMESTAMP": timestamp,
            "HTTP_X_RESOLVER_SIGNATURE": base64.b64encode(signature).decode(),
        }
    )
    return request


class BaseAuthTest(SimpleTestCase):
    def setUp(self):
        cache.delete(ResolverSignatureAuth.discovery_cache_key)
        self.factory = RequestFactory()


@override_settings(RESOLVER_TRUSTED_KEYS=BUNDLE_SPEC)
class ResolverSignatureBundleTest(BaseAuthTest):
    def test_key_id_selects_the_matching_key(self):
        request = _signed_request(
            self.factory,
            path="/api/internal/rotation/value-due/",
            signing_key=NEW_KEY,
            key_id="next",
        )
        self.assertEqual(ResolverSignatureAuth().authenticate(request, None), "next")

    def test_signed_by_other_key_is_rejected(self):
        request = _signed_request(
            self.factory,
            path="/api/internal/rotation/value-due/",
            signing_key=NEW_KEY,
            key_id="primary",
        )
        self.assertIsNone(ResolverSignatureAuth().authenticate(request, None))

    def test_unknown_key_id_is_rejected(self):
        request = _signed_request(
            self.factory,
            path="/api/internal/rotation/value-due/",
            signing_key=NEW_KEY,
            key_id="missing",
        )
        self.assertIsNone(ResolverSignatureAuth().authenticate(request, None))


class ResolverSignatureDiscoveryTest(BaseAuthTest):
    @override_settings(
        RESOLVER_TRUSTED_KEYS="",
        RESOLVER_URL="https://resolver.example",
    )
    def test_key_is_discovered_and_cached(self):
        body = ('{"key_id":"discovered","public_key":"' + bytes(NEW_KEY.verify_key).hex() + '"}').encode()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return body

        with patch("apps.accounts.auth.urllib.request.urlopen", return_value=FakeResponse()) as fetch:
            request = _signed_request(
                self.factory,
                path="/api/internal/rotation/value-due/",
                signing_key=NEW_KEY,
                key_id="discovered",
            )
            self.assertEqual(ResolverSignatureAuth().authenticate(request, None), "discovered")
            self.assertEqual(ResolverSignatureAuth().authenticate(request, None), "discovered")
            self.assertEqual(fetch.call_count, 1)

    @override_settings(
        RESOLVER_TRUSTED_KEYS="",
        RESOLVER_URL="https://resolver.example",
    )
    def test_discovery_failure_fails_closed(self):
        with patch("apps.accounts.auth.urllib.request.urlopen", side_effect=OSError("offline")):
            request = _signed_request(
                self.factory,
                path="/api/internal/rotation/value-due/",
                signing_key=NEW_KEY,
                key_id="discovered",
            )
            self.assertIsNone(ResolverSignatureAuth().authenticate(request, None))
