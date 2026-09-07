"""
Unit & Integration Tests for CryptoAPI-Safe Auto-Fix & Remediation Engine.
"""

import unittest
from analyzer.scanner import auto_fix_code, scan_code_full


class TestCodeFixer(unittest.TestCase):
    def test_fix_draft_names(self):
        code = """import oqs
with oqs.KeyEncapsulation("Kyber512") as kem:
    pk = kem.generate_keypair()
"""
        res = auto_fix_code(code)
        self.assertTrue(res["success"])
        self.assertTrue(res["has_changes"])
        self.assertIn("ML-KEM-512", res["fixed_code"])
        self.assertNotIn("Kyber512", res["fixed_code"])
        self.assertIn("--- original.py", res["diff"])

    def test_fix_pqc_key_confusion(self):
        code = """import oqs
with oqs.Signature("ML-DSA-65") as signer:
    public_key = signer.generate_keypair()
    signature = signer.sign(message, public_key)
"""
        res = auto_fix_code(code)
        self.assertTrue(res["success"])
        self.assertTrue(res["has_changes"])
        self.assertIn("signer.sign(message)", res["fixed_code"])
        self.assertNotIn("public_key)", res["fixed_code"])

    def test_fix_weak_prng(self):
        code = """import random
seed_int = random.randint(100000, 999999)
"""
        res = auto_fix_code(code)
        self.assertTrue(res["success"])
        self.assertTrue(res["has_changes"])
        self.assertIn("import secrets", res["fixed_code"])
        self.assertNotIn("import random", res["fixed_code"])

    def test_fix_unverified_signature(self):
        code = """import oqs
with oqs.Signature("ML-DSA-65") as signer:
    pk = signer.generate_keypair()
    sig = signer.sign(b"data")
    signer.verify(b"data", sig, pk)
"""
        res = auto_fix_code(code)
        self.assertTrue(res["success"])
        self.assertTrue(res["has_changes"])
        self.assertIn("is_valid = signer.verify(b\"data\", sig, pk)", res["fixed_code"])
        self.assertIn("assert is_valid", res["fixed_code"])

    def test_fix_insecure_hybrid_xor(self):
        code = """classical_secret = get_classical_shared_secret()
pqc_secret = get_pqc_shared_secret()

hybrid_secret = bytes(
    a ^ b for a, b in zip(classical_secret, pqc_secret)
)
use_key(hybrid_secret)
"""
        res = auto_fix_code(code)
        self.assertTrue(res["success"])
        self.assertTrue(res["has_changes"])
        self.assertIn("HKDF", res["fixed_code"])
        self.assertIn("derive(classical_secret + pqc_secret)", res["fixed_code"])

    def test_remediated_code_reaches_clean_status(self):
        # Taking scenario 6 (draft name) and fixing it
        code = """import oqs
with oqs.KeyEncapsulation("Kyber512") as kem:
    pk = kem.generate_keypair()
"""
        fix_res = auto_fix_code(code)
        scan_res = scan_code_full(fix_res["fixed_code"])
        self.assertEqual(scan_res["readiness_score"], 100)
        self.assertEqual(scan_res["grade"], "A")
        self.assertEqual(scan_res["total_findings"], 0)


if __name__ == "__main__":
    unittest.main()
