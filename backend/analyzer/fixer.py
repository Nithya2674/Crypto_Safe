"""
CryptoAPI-Safe Automated Remediation Engine.
Transforms vulnerable cryptographic code into secure, standards-compliant code
and generates unified patch diffs.
"""

import re
import difflib
from typing import Dict, Any, List, Tuple


class CodeFixer:
    """
    Analyzes Python source code for detected cryptographic misuses
    and generates automated compliant fixes.
    """

    # Mapping of draft names to standardized NIST FIPS names
    DRAFT_REPLACEMENTS = [
        (r'["\']Kyber512["\']', '"ML-KEM-512"', "Standardized draft 'Kyber512' to NIST FIPS 203 'ML-KEM-512'"),
        (r'["\']Kyber768["\']', '"ML-KEM-768"', "Standardized draft 'Kyber768' to NIST FIPS 203 'ML-KEM-768'"),
        (r'["\']Kyber1024["\']', '"ML-KEM-1024"', "Standardized draft 'Kyber1024' to NIST FIPS 203 'ML-KEM-1024'"),
        (r'["\']Kyber-512["\']', '"ML-KEM-512"', "Standardized draft 'Kyber-512' to NIST FIPS 203 'ML-KEM-512'"),
        (r'["\']Kyber-768["\']', '"ML-KEM-768"', "Standardized draft 'Kyber-768' to NIST FIPS 203 'ML-KEM-768'"),
        (r'["\']Kyber-1024["\']', '"ML-KEM-1024"', "Standardized draft 'Kyber-1024' to NIST FIPS 203 'ML-KEM-1024'"),
        (r'["\']Dilithium2["\']', '"ML-DSA-44"', "Standardized draft 'Dilithium2' to NIST FIPS 204 'ML-DSA-44'"),
        (r'["\']Dilithium3["\']', '"ML-DSA-65"', "Standardized draft 'Dilithium3' to NIST FIPS 204 'ML-DSA-65'"),
        (r'["\']Dilithium5["\']', '"ML-DSA-87"', "Standardized draft 'Dilithium5' to NIST FIPS 204 'ML-DSA-87'"),
        (r'["\']Dilithium-2["\']', '"ML-DSA-44"', "Standardized draft 'Dilithium-2' to NIST FIPS 204 'ML-DSA-44'"),
        (r'["\']Dilithium-3["\']', '"ML-DSA-65"', "Standardized draft 'Dilithium-3' to NIST FIPS 204 'ML-DSA-65'"),
        (r'["\']Dilithium-5["\']', '"ML-DSA-87"', "Standardized draft 'Dilithium-5' to NIST FIPS 204 'ML-DSA-87'"),
        (r'["\']SPHINCS\+["\']', '"SLH-DSA"', "Standardized draft 'SPHINCS+' to NIST FIPS 205 'SLH-DSA'"),
    ]

    def fix(self, code: str) -> Dict[str, Any]:
        """
        Applies automated fixes to code and returns original, fixed, diff, and applied fixes.
        """
        original_code = code
        modified_code = code
        applied_fixes: List[str] = []

        # 1. Fix FIPS Draft Names
        modified_code, draft_fixes = self._fix_fips_draft_names(modified_code)
        applied_fixes.extend(draft_fixes)

        # 2. Fix PQC Key Confusion in sign()
        modified_code, key_fixes = self._fix_pqc_key_confusion(modified_code)
        applied_fixes.extend(key_fixes)

        # 3. Fix Insecure PRNG (random -> secrets)
        modified_code, prng_fixes = self._fix_weak_prng(modified_code)
        applied_fixes.extend(prng_fixes)

        # 4. Fix Unverified Signatures
        modified_code, sig_fixes = self._fix_unverified_signatures(modified_code)
        applied_fixes.extend(sig_fixes)

        # 5. Fix Insecure Hybrid Byte XOR -> HKDF
        modified_code, hybrid_fixes = self._fix_insecure_hybrid(modified_code)
        applied_fixes.extend(hybrid_fixes)

        # Generate Unified Diff
        diff_text = self._generate_diff(original_code, modified_code)

        return {
            "success": True,
            "original_code": original_code,
            "fixed_code": modified_code,
            "has_changes": original_code != modified_code,
            "diff": diff_text,
            "applied_fixes": applied_fixes
        }

    def _fix_fips_draft_names(self, code: str) -> Tuple[str, List[str]]:
        fixes = []
        result = code
        for pattern, replacement, desc in self.DRAFT_REPLACEMENTS:
            if re.search(pattern, result, re.IGNORECASE):
                result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
                fixes.append(desc)
        return result, fixes

    def _fix_pqc_key_confusion(self, code: str) -> Tuple[str, List[str]]:
        fixes = []
        result = code

        # Pattern: signer.sign(message, public_key) -> signer.sign(message)
        # In liboqs, signer.sign() only requires the message because the private key is held internally
        pattern = r'(signer\.sign\s*\(\s*[\w\.\'\"\-]+)\s*,\s*(?:public_key|pk|pub_key|public|pubkey)\s*\)'
        if re.search(pattern, result, re.IGNORECASE):
            result = re.sub(pattern, r'\1)', result, flags=re.IGNORECASE)
            fixes.append("Removed erroneous public key parameter from ML-DSA signer.sign(message)")

        # Pattern: multiline signature = signer.sign(\n    message,\n    public_key\n)
        multiline_pattern = r'(\.sign\s*\(\s*[\w\.\'\"\-]+)\s*,\s*[\s\n\r]*(?:public_key|pk|pub_key|public|pubkey)[\s\n\r]*\)'
        if re.search(multiline_pattern, result, re.IGNORECASE):
            result = re.sub(multiline_pattern, r'\1)', result, flags=re.IGNORECASE)
            if "Removed erroneous public key parameter from ML-DSA signer.sign(message)" not in fixes:
                fixes.append("Removed erroneous public key parameter from ML-DSA signer.sign(message)")

        return result, fixes

    def _fix_weak_prng(self, code: str) -> Tuple[str, List[str]]:
        fixes = []
        result = code

        has_weak_random = bool(re.search(r'\brandom\.(?:randint|random|choice|getrandbits)\b', result))

        if has_weak_random:
            # Replace import random with import secrets
            if re.search(r'^\s*import random\s*$', result, re.MULTILINE):
                result = re.sub(r'^\s*import random\s*$', 'import secrets', result, flags=re.MULTILINE)
                fixes.append("Replaced 'import random' with cryptographically secure 'import secrets'")
            elif "import secrets" not in result:
                result = "import secrets\n" + result
                fixes.append("Added 'import secrets' module")

            # Replace random.randint(100000, 999999) or similar with secrets.token_bytes(32)
            randint_pattern = r'random\.randint\s*\([^)]*\)'
            if re.search(randint_pattern, result):
                result = re.sub(randint_pattern, 'secrets.randbelow(1_000_000)', result)
                fixes.append("Replaced insecure random.randint with secrets.randbelow")

            random_call_pattern = r'random\.random\s*\(\s*\)'
            if re.search(random_call_pattern, result):
                result = re.sub(random_call_pattern, 'secrets.token_bytes(32)', result)
                fixes.append("Replaced insecure random.random() with secrets.token_bytes(32)")

        return result, fixes

    def _fix_unverified_signatures(self, code: str) -> Tuple[str, List[str]]:
        fixes = []
        result = code

        # Match bare signer.verify(...) statements (not preceded by =, if, assert, return)
        # e.g. "    signer.verify(b"msg", sig, pk)"
        lines = result.splitlines()
        new_lines = []
        modified = False

        for line in lines:
            stripped = line.strip()
            # If line is a bare call to verify
            if (stripped.startswith("signer.verify(") or stripped.startswith("kem.verify(")) and not any(
                stripped.startswith(prefix) for prefix in ["if ", "assert ", "return ", "is_valid = ", "valid = ", "result = "]
            ):
                indent = line[:len(line) - len(line.lstrip())]
                # Replace with: is_valid = signer.verify(...) \n assert is_valid, "Signature validation failed!"
                call_part = stripped
                new_lines.append(f"{indent}is_valid = {call_part}")
                new_lines.append(f'{indent}assert is_valid, "Cryptographic signature validation failed!"')
                modified = True
            else:
                new_lines.append(line)

        if modified:
            result = "\n".join(new_lines)
            fixes.append("Wrapped bare verify() call with 'is_valid = signer.verify(...)' and security assertion check")

        return result, fixes

    def _fix_insecure_hybrid(self, code: str) -> Tuple[str, List[str]]:
        fixes = []
        result = code

        # Pattern: hybrid_secret = bytes(a ^ b for a, b in zip(classical_secret, pqc_secret))
        zip_xor_pattern = r'(\w+)\s*=\s*bytes\s*\(\s*\w+\s*\^\s*\w+\s+for\s+\w+\s*,\s*\w+\s+in\s+zip\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*\)'
        match = re.search(zip_xor_pattern, result)

        if match:
            target_var = match.group(1)
            s1 = match.group(2)
            s2 = match.group(3)

            hkdf_replacement = (
                f"# Cryptographically secure HKDF hybrid combination (NIST SP 800-56C Rev 2)\n"
                f"from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
                f"from cryptography.hazmat.primitives import hashes\n\n"
                f"{target_var} = HKDF(\n"
                f"    algorithm=hashes.SHA256(),\n"
                f"    length=32,\n"
                f"    salt=b'PQC-Hybrid-Salt-v1',\n"
                f"    info=b'PQC-Hybrid-Key-v1'\n"
                f").derive({s1} + {s2})"
            )

            result = re.sub(zip_xor_pattern, hkdf_replacement, result)
            fixes.append(f"Replaced naive byte XOR combination of {s1} and {s2} with NIST SP 800-56C compliant HKDF-SHA256")

        return result, fixes

    def _generate_diff(self, original: str, modified: str) -> str:
        orig_lines = original.splitlines(keepends=True)
        mod_lines = modified.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            mod_lines,
            fromfile="original.py",
            tofile="remediated.py",
            lineterm=""
        )
        return "".join(diff)
