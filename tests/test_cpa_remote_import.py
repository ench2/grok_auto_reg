import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cpa_export import import_auth_file_to_remote_cpa


class RemoteCpaImportTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_path = Path(self.temp_dir.name) / "xai-user@example.com.json"
        self.auth_path.write_text(json.dumps({"type": "xai", "email": "user@example.com"}), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("cpa_export.requests.post")
    def test_uploads_multipart_with_bearer_auth(self, post):
        response = Mock(status_code=200, text='{"success":true}')
        response.json.return_value = {"success": True}
        post.return_value = response

        result = import_auth_file_to_remote_cpa(
            self.auth_path,
            base_url="http://cpa.example:8317/",
            management_key="secret",
            timeout=12,
        )

        self.assertTrue(result["ok"])
        _, kwargs = post.call_args
        self.assertEqual(kwargs["headers"], {"Authorization": "Bearer secret"})
        self.assertEqual(kwargs["timeout"], 12)
        self.assertIn("multipart", kwargs)

    @patch("cpa_export.requests.post")
    def test_http_error_is_non_fatal_result(self, post):
        post.return_value = Mock(status_code=401, text="unauthorized")
        result = import_auth_file_to_remote_cpa(
            self.auth_path, base_url="http://cpa.example:8317", management_key="bad"
        )
        self.assertFalse(result["ok"])
        self.assertIn("HTTP 401", result["error"])

    @patch("cpa_export.requests.post")
    def test_non_json_success_is_rejected(self, post):
        response = Mock(status_code=200, text="OK")
        response.json.side_effect = ValueError("not json")
        post.return_value = response
        result = import_auth_file_to_remote_cpa(
            self.auth_path, base_url="http://cpa.example:8317", management_key="secret"
        )
        self.assertFalse(result["ok"])
        self.assertIn("not valid JSON", result["error"])

    @patch("cpa_export.requests.post", side_effect=TimeoutError("timeout"))
    def test_timeout_is_non_fatal_result(self, _post):
        result = import_auth_file_to_remote_cpa(
            self.auth_path, base_url="http://cpa.example:8317", management_key="secret"
        )
        self.assertFalse(result["ok"])
        self.assertIn("request failed", result["error"])


if __name__ == "__main__":
    unittest.main()
