import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext
from .base import BaseRule


class UnverifiedSignatureRule(BaseRule):
    rule_id = "PQC-SIG-004"
    name = "Ignored Signature Verification Result"
    category = "Verification & Validation"
    severity = Severity.HIGH
    cwe = "CWE-347"
    nist_ref = "NIST FIPS 204"
    description = (
        "Detects signature verification calls (e.g., signer.verify(...)) executed as bare statements "
        "without inspecting or validating the boolean return value."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            # Check if this is an Expr statement (a statement whose value is ignored/discarded)
            if isinstance(node, ast.Expr):
                value = node.value
                if isinstance(value, ast.Call):
                    func = value.func
                    func_name = ""
                    if isinstance(func, ast.Attribute):
                        func_name = func.attr
                    elif isinstance(func, ast.Name):
                        func_name = func.id

                    if func_name in ("verify", "verify_signature", "check_signature"):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="UNCHECKED_VERIFICATION",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm="Digital Signature (ML-DSA / SLH-DSA)",
                            api=f"{func_name}()",
                            line=node.lineno,
                            message=(
                                f"Signature verification '{func_name}()' result is ignored. "
                                f"Verification APIs return a boolean (True/False); without checking this result, "
                                f"tampered, replayed, or forged signatures will silently succeed."
                            ),
                            recommendation=(
                                "Verify the return value using an assertion or explicit conditional check, e.g.: "
                                "'is_valid = signer.verify(...)', 'if not signer.verify(...): raise ValueError(\"Invalid signature\")' "
                                "or 'assert signer.verify(...)'."
                            ),
                            cwe=self.cwe,
                            nist_ref=self.nist_ref
                        ))

        return findings
