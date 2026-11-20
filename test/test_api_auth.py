import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

_TEST_DB_DIR = tempfile.TemporaryDirectory(prefix="cyber-api-auth-")
with patch.dict(os.environ, {"CYBER_EVIDENCE_DB": str(Path(_TEST_DB_DIR.name) / "evidence.sqlite")}):
    import api


class ApiTokenAuthTests(unittest.TestCase):
    def test_health_is_open_when_no_token_is_configured(self):
        with patch.dict(os.environ, {"CYBER_API_TOKEN": ""}):
            with TestClient(api.app) as client:
                response = client.get("/api/health")

        self.assertEqual(response.status_code, 200)

    def test_health_requires_bearer_token_when_configured(self):
        with patch.dict(os.environ, {"CYBER_API_TOKEN": "test-secret-token"}):
            with TestClient(api.app) as client:
                response = client.get("/api/health")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Authentication required."})

    def test_health_accepts_correct_bearer_token(self):
        with patch.dict(os.environ, {"CYBER_API_TOKEN": "test-secret-token"}):
            with TestClient(api.app) as client:
                response = client.get(
                    "/api/health",
                    headers={"Authorization": "Bearer test-secret-token"},
                )

        self.assertEqual(response.status_code, 200)

    def test_websocket_rejects_connection_without_token(self):
        with patch.dict(os.environ, {"CYBER_API_TOKEN": "test-secret-token"}):
            with TestClient(api.app) as client:
                with client.websocket_connect("/ws/events") as websocket:
                    websocket.send_json({"type": "auth"})
                    with self.assertRaises(WebSocketDisconnect) as disconnect:
                        websocket.receive_json()

        self.assertEqual(disconnect.exception.code, 1008)

    def test_unhandled_exception_response_hides_raw_exception_text(self):
        secret_detail = "sensitive-internal-error-marker"
        with patch.dict(os.environ, {"CYBER_API_TOKEN": ""}):
            with patch.object(api.local_rag, "model_status", side_effect=RuntimeError(secret_detail)):
                with TestClient(api.app, raise_server_exceptions=False) as client:
                    response = client.get("/api/health")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "Internal server error."})
        self.assertNotIn(secret_detail, response.text)


if __name__ == "__main__":
    unittest.main()
