"""Unit tests for Groq AI remediation integration (mocked external calls only)."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
from groq import AuthenticationError, PermissionDeniedError

import groq_service
from app import app


SAMPLE_CODE = 'import oqs\nkem = oqs.KeyEncapsulation("Kyber512")'


def _completion_with_content(content: str) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


def _http_error_response(status_code: int) -> httpx.Response:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    return httpx.Response(status_code, request=request)


class TestGroqService(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_missing_groq_api_key(self):
        with patch.dict("os.environ", {"GROQ_API_KEY": ""}, clear=False):
            with patch("groq_service.get_groq_api_key", return_value=None):
                result = groq_service.generate_ai_fix(SAMPLE_CODE, findings=[])

        self.assertTrue(result["success"])
        self.assertEqual(result["source"], "fallback")
        self.assertIn("missing", result["fallback_reason"].lower())
        self.assertTrue(result["fallback"])

    def test_malformed_key(self):
        with patch("groq_service.get_groq_api_key", return_value="not-a-valid-key"):
            with patch("groq_service.is_key_format_valid", return_value=False):
                result = groq_service.generate_ai_fix(SAMPLE_CODE, findings=[])

        self.assertTrue(result["success"])
        self.assertEqual(result["source"], "fallback")
        self.assertIn("invalid", result["fallback_reason"].lower())
        self.assertTrue(result["fallback"])

    def test_successful_groq_response(self):
        payload = {
            "status": "confirmed",
            "overall_severity": "HIGH",
            "summary": "Legacy KEM name detected.",
            "fix_recommendation": "Use ML-KEM-512.",
            "secure_code": 'kem = oqs.KeyEncapsulation("ML-KEM-512")',
            "why_it_is_wrong": "Kyber512 is deprecated naming.",
            "confidence": 0.91,
        }
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _completion_with_content(
            json.dumps(payload)
        )

        with patch("groq_service.get_groq_api_key", return_value="gsk_abcdefghijklmnopqrstuvwxyz0123456789"):
            with patch("groq_service.is_key_format_valid", return_value=True):
                with patch("groq_service.get_groq_model", return_value="llama-3.1-8b-instant"):
                    with patch("groq_service._build_client", return_value=mock_client):
                        result = groq_service.generate_ai_fix(SAMPLE_CODE, findings=[{"id": 1}])

        self.assertTrue(result["success"])
        self.assertEqual(result["source"], "groq")
        self.assertFalse(result.get("fallback", False))
        self.assertNotIn("fallback_reason", result)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["overall_severity"], "HIGH")
        self.assertIn("ML-KEM-512", result["secure_code"])
        mock_client.chat.completions.create.assert_called_once()
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertEqual(kwargs["response_format"], {"type": "json_object"})

    def test_http_403_response(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = PermissionDeniedError(
            "Forbidden",
            response=_http_error_response(403),
            body={"error": {"message": "Invalid API Key"}},
        )

        with patch("groq_service.get_groq_api_key", return_value="gsk_abcdefghijklmnopqrstuvwxyz0123456789"):
            with patch("groq_service.is_key_format_valid", return_value=True):
                with patch("groq_service.get_groq_model", return_value="llama-3.1-8b-instant"):
                    with patch("groq_service._build_client", return_value=mock_client):
                        result = groq_service.generate_ai_fix(SAMPLE_CODE, findings=[])

        self.assertTrue(result["success"])
        self.assertEqual(result["source"], "fallback")
        self.assertIn("403", result["fallback_reason"])
        self.assertNotIn("gsk_", result["fallback_reason"])

    def test_fallback_response_includes_reason(self):
        with patch(
            "groq_service._call_groq_api",
            side_effect=groq_service.GroqServiceError(
                "network_failure",
                "Could not reach the Groq API (network/DNS failure).",
            ),
        ):
            result = groq_service.generate_ai_fix(SAMPLE_CODE, findings=[])

        self.assertEqual(result["source"], "fallback")
        self.assertEqual(
            result["fallback_reason"],
            "Could not reach the Groq API (network/DNS failure).",
        )
        self.assertIn("diff", result)
        self.assertIn("applied_fixes", result)

    def test_ai_status_missing_key(self):
        with patch("groq_service.get_groq_api_key", return_value=None):
            with patch("groq_service.get_groq_model", return_value="llama-3.1-8b-instant"):
                status = groq_service.probe_groq_connection()

        self.assertFalse(status["configured"])
        self.assertFalse(status["key_format_valid"])
        self.assertEqual(status["key_length"], 0)
        self.assertFalse(status["api_reachable"])
        self.assertFalse(status["authenticated"])
        self.assertIn("missing", status["error"].lower())
        self.assertTrue(all(k != "api_key" for k in status.keys()))

    def test_ai_status_endpoint_shape(self):
        fake_status = {
            "configured": True,
            "key_format_valid": True,
            "key_length": 56,
            "model": "llama-3.1-8b-instant",
            "api_reachable": True,
            "authenticated": False,
            "error": "Groq rejected the API key (HTTP 403).",
        }
        with patch("app.probe_groq_connection", return_value=fake_status):
            response = self.client.get("/api/ai-status")

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(
            set(data.keys()),
            {
                "configured",
                "key_format_valid",
                "key_length",
                "model",
                "api_reachable",
                "authenticated",
                "error",
            },
        )
        self.assertFalse(data["authenticated"])
        serialized = json.dumps(data)
        self.assertNotIn("gsk_", serialized)


class TestGroqAuthClassification(unittest.TestCase):
    def test_authentication_error_maps_to_401_message(self):
        exc = AuthenticationError(
            "Unauthorized",
            response=_http_error_response(401),
            body={"error": {"message": "Invalid API Key"}},
        )
        classified = groq_service._classify_sdk_error(exc)
        self.assertEqual(classified.code, "auth_failure")
        self.assertIn("401", classified.message)


if __name__ == "__main__":
    unittest.main()
