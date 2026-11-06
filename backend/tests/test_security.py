import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from twilio.request_validator import RequestValidator
from channels.twilio_handler import router
from security.sanitizer import sanitize_message


class SecurityTests(unittest.TestCase):
    def test_sanitization_removes_complete_email_and_card(self):
        result = sanitize_message("Contact victim@example.com about card 1234 5678 9012 3456 and OTP: 123456")
        self.assertNotIn("victim", result.sanitized_message)
        self.assertNotIn("example.com", result.sanitized_message)
        self.assertNotIn("3456", result.sanitized_message)
        self.assertNotIn("123456", result.sanitized_message)
        self.assertIn("[EMAIL]", result.sanitized_message)
        self.assertIn("[CARD]", result.sanitized_message)

    def test_webhook_missing_configuration_and_invalid_signature(self):
        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as client:
            body = {"Body": "test suspicious message", "From": "+10000000000"}
            with patch.dict(os.environ, {"TWILIO_AUTH_TOKEN": "", "TWILIO_WEBHOOK_BASE_URL": ""}):
                self.assertEqual(client.post("/webhook/sms", data=body).status_code, 503)
            with patch.dict(os.environ, {"TWILIO_AUTH_TOKEN": "unit-test-signature-key", "TWILIO_WEBHOOK_BASE_URL": ""}):
                self.assertEqual(client.post("/webhook/sms", data=body).status_code, 403)

    def test_valid_webhook_signature_passes_before_form_validation(self):
        app = FastAPI()
        app.include_router(router)
        url = "http://testserver/webhook/sms"
        key = "unit-test-signature-key"
        body = {"Body": "test suspicious message"}
        signature = RequestValidator(key).compute_signature(url, body)
        with patch.dict(os.environ, {"TWILIO_AUTH_TOKEN": key, "TWILIO_WEBHOOK_BASE_URL": ""}):
            with TestClient(app) as client:
                response = client.post("/webhook/sms", data=body, headers={"X-Twilio-Signature": signature})
                self.assertEqual(response.status_code, 422)
                response = client.post("/webhook/sms", data={"Body": "tampered message"}, headers={"X-Twilio-Signature": signature})
                self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
