from unittest.mock import patch
from django.test import TestCase
from django.core.cache import cache

class StatusEndpointTests(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()

    def test_status_endpoint_success(self):
        """
        Verify status endpoint returns 200 OK and all components are healthy.
        """
        response = self.client.get("/api/status/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["status"], "healthy")
        self.assertIn("timestamp", data)
        self.assertIn("uptime_seconds", data)
        
        components = data["components"]
        self.assertEqual(components["database"]["status"], "healthy")
        self.assertEqual(components["database"]["read_ok"], True)
        self.assertEqual(components["database"]["write_ok"], True)
        
        self.assertEqual(components["functional_checks"]["status"], "healthy")
        self.assertNotIn("error", components["functional_checks"]["details"])
        
        self.assertEqual(components["cache"]["status"], "healthy")
        self.assertEqual(components["encryption"]["status"], "healthy")
        self.assertEqual(components["filesystem"]["status"], "healthy")
        
        self.assertIn("system", data)
        self.assertIn("django_version", data["system"])
        self.assertIn("python_version", data["system"])

    def test_status_health_alias(self):
        """
        Verify status/health/ alias returns the same healthy structure.
        """
        response = self.client.get("/api/status/health/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")

    @patch("django.db.connection.cursor")
    def test_status_database_failure(self, mock_cursor):
        """
        Verify status endpoint returns 503 if the database is offline or fails to query.
        """
        mock_cursor.side_effect = Exception("Connection refused")
        response = self.client.get("/api/status/")
        self.assertEqual(response.status_code, 503)
        data = response.json()
        
        self.assertEqual(data["status"], "unhealthy")
        self.assertEqual(data["components"]["database"]["status"], "unhealthy")
        self.assertEqual(data["components"]["database"]["read_ok"], False)
        self.assertEqual(data["components"]["database"]["write_ok"], False)
        self.assertIn("Connection refused", data["components"]["database"]["details"]["error"])
        
        # Functional checks should also be unhealthy because DB was down
        self.assertEqual(data["components"]["functional_checks"]["status"], "unhealthy")

    @patch("django.core.cache.cache.set")
    def test_status_cache_failure(self, mock_cache_set):
        """
        Verify status endpoint returns 503 if cache set raises an exception.
        """
        mock_cache_set.side_effect = Exception("Cache timeout")
        response = self.client.get("/api/status/")
        self.assertEqual(response.status_code, 503)
        data = response.json()
        
        self.assertEqual(data["status"], "unhealthy")
        self.assertEqual(data["components"]["cache"]["status"], "unhealthy")
        self.assertIn("Cache timeout", data["components"]["cache"]["details"]["error"])

    @patch("apps.common.services.encryption.EncryptionService.encrypt")
    def test_status_encryption_failure(self, mock_encrypt):
        """
        Verify status endpoint returns 503 if encryption service fails.
        """
        mock_encrypt.side_effect = Exception("Encryption key corrupted")
        response = self.client.get("/api/status/")
        self.assertEqual(response.status_code, 503)
        data = response.json()
        
        self.assertEqual(data["status"], "unhealthy")
        self.assertEqual(data["components"]["encryption"]["status"], "unhealthy")
        self.assertIn("Encryption key corrupted", data["components"]["encryption"]["details"]["error"])

    @patch("shutil.disk_usage")
    def test_status_filesystem_failure(self, mock_disk_usage):
        """
        Verify status endpoint handles filesystem/disk usage failure.
        """
        mock_disk_usage.side_effect = Exception("Disk read error")
        response = self.client.get("/api/status/")
        self.assertEqual(response.status_code, 503)
        data = response.json()
        
        self.assertEqual(data["status"], "unhealthy")
        self.assertEqual(data["components"]["filesystem"]["status"], "unhealthy")
        self.assertIn("Disk read error", data["components"]["filesystem"]["details"]["error"])
