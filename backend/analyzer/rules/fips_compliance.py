import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext
from .base import BaseRule

DRAFT_TO_STANDARD = {
    "kyber512": ("Kyber512", "ML-KEM-512", "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)"),
    "kyber768": ("Kyber768", "ML-KEM-768", "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)"),
    "kyber1024": ("Kyber1024", "ML-KEM-1024", "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)"),
    "kyber-512": ("Kyber-512", "ML-KEM-512", "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)"),
    "kyber-768": ("Kyber-768", "ML-KEM-768", "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)"),
    "kyber-1024": ("Kyber-1024", "ML-KEM-1024", "NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)"),
    "dilithium2": ("Dilithium2", "ML-DSA-44", "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)"),
    "dilithium3": ("Dilithium3", "ML-DSA-65", "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)"),
    "dilithium5": ("Dilithium5", "ML-DSA-87", "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)"),
    "dilithium-2": ("Dilithium-2", "ML-DSA-44", "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)"),
    "dilithium-3": ("Dilithium-3", "ML-DSA-65", "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)"),
    "dilithium-5": ("Dilithium-5", "ML-DSA-87", "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)"),
    "sphincs+": ("SPHINCS+", "SLH-DSA", "NIST FIPS 205 (Stateless Hash-Based Digital Signature Standard)"),
    "sphincs": ("SPHINCS", "SLH-DSA", "NIST FIPS 205 (Stateless Hash-Based Digital Signature Standard)"),
}


class FIPSComplianceRule(BaseRule):
    rule_id = "PQC-FIPS-006"
    name = "Deprecated Pre-Standard PQC Draft Naming"
    category = "FIPS Compliance"
    severity = Severity.MEDIUM
    cwe = "CWE-1026"
    nist_ref = "NIST FIPS 203 / 204 / 205"
    description = (
        "Detects pre-standard draft names (Kyber, Dilithium, SPHINCS+) in algorithm parameters. "
        "NIST officially finalized FIPS 203, 204, and 205 standards in August 2024."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []
        flagged_lines = set()

        for node in ast.walk(tree):
            # Check string literals (constants) representing algorithm names
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val_lower = node.value.strip().lower()
                for draft_key, (draft_name, standard_name, standard_title) in DRAFT_TO_STANDARD.items():
                    if (val_lower == draft_key or draft_key in val_lower) and node.lineno not in flagged_lines:
                        flagged_lines.add(node.lineno)
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="NON_STANDARD_FIPS_NAME",
                            category=self.category,
                            severity=Severity.MEDIUM,
                            algorithm=draft_name,
                            api=f"'{node.value}'",
                            line=node.lineno,
                            message=(
                                f"Deprecated pre-standard draft identifier '{node.value}' found. "
                                f"In August 2024, NIST officially published the final standards under new standardized designations."
                            ),
                            recommendation=(
                                f"Migrate from draft parameter '{node.value}' to the official standard: '{standard_name}'. "
                                f"Specification: {standard_title}."
                            ),
                            cwe=self.cwe,
                            nist_ref=self.nist_ref
                        ))

        return findings
