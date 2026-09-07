import unittest
import json
from app import app


class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["engine"], "Modular AST Rule Engine")
        self.assertEqual(data["rules_count"], 8)

    def test_list_rules_endpoint(self):
        response = self.client.get("/api/rules")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertEqual(data["total_rules"], 8)
        self.assertEqual(len(data["rules"]), 8)

    def test_scan_endpoint_with_findings(self):
        code = """
import random
import oqs

key = b"hardcoded_private_key_12345"
seed = random.randint(1, 100)
with oqs.Signature("Dilithium3") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"msg", pk)
    signer.verify(b"msg", sig, pk)
"""
        response = self.client.post(
            "/api/scan",
            data=json.dumps({"code": code}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["total_findings"], 4)
        self.assertIn("readiness_score", data)
        self.assertIn("grade", data)
        self.assertIn("cbom", data)
        self.assertIn("summary", data)

    def test_scan_endpoint_with_syntax_error(self):
        broken_code = "def broken_python_code(:"
        response = self.client.post(
            "/api/scan",
            data=json.dumps({"code": broken_code}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertFalse(data["success"])
        self.assertEqual(data["total_findings"], 1)
        self.assertEqual(data["findings"][0]["type"], "SYNTAX_ERROR")
        self.assertIn("summary", data)
        self.assertEqual(data["readiness_score"], 0)

    def test_fix_endpoint(self):
        code = 'import oqs\nkem = oqs.KeyEncapsulation("Kyber512")'
        response = self.client.post(
            "/api/fix",
            data=json.dumps({"code": code}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data["success"])
        self.assertTrue(data["has_changes"])
        self.assertIn("ML-KEM-512", data["fixed_code"])
        self.assertGreaterEqual(len(data["applied_fixes"]), 1)
        self.assertIn("--- original.py", data["diff"])


if __name__ == "__main__":
    unittest.main()
