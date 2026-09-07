import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext
from .base import BaseRule

VULNERABLE_ALGORITHMS = {
    "rsa": ("RSA", "Digital Signatures / Asymmetric Encryption", "ML-DSA (FIPS 204) or ML-KEM (FIPS 203)"),
    "dsa": ("DSA", "Digital Signatures", "ML-DSA (FIPS 204)"),
    "ecdsa": ("ECDSA", "Digital Signatures", "ML-DSA (FIPS 204)"),
    "ecdh": ("ECDH", "Key Agreement", "ML-KEM (FIPS 203)"),
    "ed25519": ("Ed25519", "Digital Signatures", "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"),
    "x25519": ("X25519", "Key Exchange", "ML-KEM-768 (FIPS 203) or Hybrid X25519+ML-KEM"),
    "secp256k1": ("secp256k1", "Elliptic Curve Signatures", "ML-DSA (FIPS 204)"),
    "diffie_hellman": ("Diffie-Hellman", "Key Exchange", "ML-KEM (FIPS 203)"),
}


class QuantumVulnerableLegacyCryptoRule(BaseRule):
    rule_id = "PQC-LEGACY-002"
    name = "Quantum-Vulnerable Classical Cryptography"
    category = "Quantum Vulnerability"
    severity = Severity.HIGH
    cwe = "CWE-327"
    nist_ref = "NIST SP 800-227 / IR 8547"
    description = (
        "Detects classical public-key algorithms (RSA, DSA, ECDSA, ECDH, Ed25519, secp256k1) "
        "that are vulnerable to Shor's Algorithm on quantum computers (Harvest Now, Decrypt Later)."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []
        flagged_lines = set()

        for node in ast.walk(tree):
            # Check import statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name_lower = alias.name.lower()
                    for algo_key, (algo_name, purpose, pqc_replacement) in VULNERABLE_ALGORITHMS.items():
                        if algo_key in name_lower and node.lineno not in flagged_lines:
                            flagged_lines.add(node.lineno)
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                type="QUANTUM_VULNERABLE_ALGORITHM",
                                category=self.category,
                                severity=Severity.HIGH,
                                algorithm=algo_name,
                                api=alias.name,
                                line=node.lineno,
                                message=(
                                    f"Detected classical algorithm '{algo_name}' used for {purpose}. "
                                    f"This primitive is vulnerable to polynomial-time attack by Shor's algorithm on quantum computers, "
                                    f"exposing stored data to Harvest-Now-Decrypt-Later (HNDL) attacks."
                                ),
                                recommendation=(
                                    f"Migrate from {algo_name} to post-quantum standardized primitives: {pqc_replacement}. "
                                    f"Consider a hybrid classical+PQC deployment during the transition."
                                ),
                                cwe=self.cwe,
                                nist_ref=self.nist_ref
                            ))

            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").lower()
                for alias in node.names:
                    target = f"{module}.{alias.name}".lower()
                    for algo_key, (algo_name, purpose, pqc_replacement) in VULNERABLE_ALGORITHMS.items():
                        if (algo_key in target or algo_key == alias.name.lower()) and node.lineno not in flagged_lines:
                            flagged_lines.add(node.lineno)
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                type="QUANTUM_VULNERABLE_ALGORITHM",
                                category=self.category,
                                severity=Severity.HIGH,
                                algorithm=algo_name,
                                api=f"{node.module}.{alias.name}",
                                line=node.lineno,
                                message=(
                                    f"Import of quantum-vulnerable primitive '{algo_name}'. "
                                    f"Shor's algorithm can solve discrete logarithm and integer factorization problems in polynomial time."
                                ),
                                recommendation=f"Replace with NIST-standardized PQC: {pqc_replacement}.",
                                cwe=self.cwe,
                                nist_ref=self.nist_ref
                            ))

            # Check direct function/class instantiation: e.g. RSA.generate(), ec.generate_private_key()
            elif isinstance(node, ast.Call):
                func_str = ""
                if isinstance(node.func, ast.Attribute):
                    func_str = node.func.attr.lower()
                    if isinstance(node.func.value, ast.Name):
                        func_str = f"{node.func.value.id}.{node.func.attr}".lower()
                elif isinstance(node.func, ast.Name):
                    func_str = node.func.id.lower()

                for algo_key, (algo_name, purpose, pqc_replacement) in VULNERABLE_ALGORITHMS.items():
                    if algo_key in func_str and node.lineno not in flagged_lines:
                        flagged_lines.add(node.lineno)
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="QUANTUM_VULNERABLE_ALGORITHM",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm=algo_name,
                            api=func_str,
                            line=node.lineno,
                            message=f"Direct invocation of quantum-vulnerable '{algo_name}' API.",
                            recommendation=f"Transition to NIST Post-Quantum standard: {pqc_replacement}.",
                            cwe=self.cwe,
                            nist_ref=self.nist_ref
                        ))

        return findings
