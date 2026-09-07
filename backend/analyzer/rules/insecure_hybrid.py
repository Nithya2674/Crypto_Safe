import ast
from typing import List, Optional, Tuple
from ..models import Finding, Severity
from ..context import AnalysisContext, KeyRole
from .base import BaseRule


class InsecureHybridKDFRule(BaseRule):
    rule_id = "PQC-HYB-008"
    name = "Insecure Hybrid Key Derivation"
    category = "Hybrid Cryptography"
    severity = Severity.HIGH
    cwe = "CWE-327"
    nist_ref = "NIST SP 800-56C Rev 2 / IETF RFC 9180"
    description = (
        "Detects naive combination (XOR via operators, zip loops, or direct byte concatenation) "
        "of classical and PQC secrets. Hybrid key exchange requires an approved KDF (e.g., HKDF-Extract-and-Expand)."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []
        flagged_lines = set()

        for node in ast.walk(tree):
            # Case 1: Generator expression or List comprehension:
            # Pattern: bytes(a ^ b for a, b in zip(classical_secret, pqc_secret))
            # or [a ^ b for a, b in zip(...)]
            if isinstance(node, (ast.GeneratorExp, ast.ListComp)):
                if isinstance(node.elt, ast.BinOp) and isinstance(node.elt.op, ast.BitXor):
                    for gen in node.generators:
                        zipped_secrets = self._extract_zip_secret_operands(gen.iter, context)
                        if zipped_secrets and node.lineno not in flagged_lines:
                            flagged_lines.add(node.lineno)
                            s1, s2 = zipped_secrets
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                type="INSECURE_HYBRID_KDF",
                                category=self.category,
                                severity=Severity.HIGH,
                                algorithm="Hybrid Key Combination (XOR)",
                                api=f"zip({s1}, {s2}) with BitXor",
                                line=node.lineno,
                                message=(
                                    f"Insecure byte-by-byte XOR combination of '{s1}' and '{s2}' detected. "
                                    f"Naive XORing of classical (ECDH) and PQC (ML-KEM) secrets is cryptographically fragile, "
                                    f"leaves the resulting hybrid key vulnerable if either primitive fails, "
                                    f"and does not provide dual-PRF security bounds."
                                ),
                                recommendation=(
                                    "Combine hybrid secrets using an approved Key Derivation Function (KDF) "
                                    "such as HKDF-Extract-and-Expand per NIST SP 800-56C Rev 2 / RFC 9180:\n"
                                    "  from cryptography.hazmat.primitives.kdf.hkdf import HKDF\n"
                                    "  from cryptography.hazmat.primitives import hashes\n"
                                    "  hybrid_key = HKDF(\n"
                                    "      algorithm=hashes.SHA256(),\n"
                                    "      length=32,\n"
                                    "      salt=b'PQC-Hybrid-Salt',\n"
                                    "      info=b'PQC-Hybrid-Key-v1'\n"
                                    f"  ).derive({s1} + {s2})"
                                ),
                                cwe=self.cwe,
                                nist_ref=self.nist_ref
                            ))

            # Case 2: For loop with zip:
            # Pattern: for a, b in zip(classical_secret, pqc_secret): ... a ^ b ...
            elif isinstance(node, ast.For):
                zipped_secrets = self._extract_zip_secret_operands(node.iter, context)
                if zipped_secrets and node.lineno not in flagged_lines:
                    # Check if body contains BitXor
                    has_xor = any(
                        isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitXor)
                        for sub in ast.walk(node)
                    )
                    if has_xor:
                        flagged_lines.add(node.lineno)
                        s1, s2 = zipped_secrets
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="INSECURE_HYBRID_KDF",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm="Hybrid Key Combination (XOR Loop)",
                            api=f"for ... in zip({s1}, {s2})",
                            line=node.lineno,
                            message=(
                                f"Insecure XOR loop combining '{s1}' and '{s2}'. "
                                f"Hybrid schemes must derive final session keys using HKDF-Extract-and-Expand."
                            ),
                            recommendation="Pass concatenated secrets into HKDF rather than looping XOR.",
                            cwe=self.cwe,
                            nist_ref=self.nist_ref
                        ))

            # Case 3: Direct binary operations:
            # Pattern: s1 ^ s2 or s1 + s2
            elif isinstance(node, ast.BinOp):
                left_name = self._extract_var_name(node.left)
                right_name = self._extract_var_name(node.right)

                if left_name and right_name and node.lineno not in flagged_lines:
                    is_secret_combination = self._is_secret_operand(left_name, context) and self._is_secret_operand(right_name, context)

                    if is_secret_combination:
                        if isinstance(node.op, ast.BitXor):
                            flagged_lines.add(node.lineno)
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                type="INSECURE_HYBRID_KDF",
                                category=self.category,
                                severity=Severity.HIGH,
                                algorithm="Hybrid Key Combination",
                                api=f"{left_name} ^ {right_name}",
                                line=node.lineno,
                                message=(
                                    f"Insecure XOR combination '{left_name} ^ {right_name}' detected. "
                                    f"Combining classical and PQC secrets via XOR does not provide dual-PRF security guarantees."
                                ),
                                recommendation=(
                                    "Combine hybrid secrets using HKDF-Extract-and-Expand per NIST SP 800-56C Rev 2: "
                                    f"HKDF(salt=..., ikm={left_name} + {right_name}, info=b'Hybrid-KEM-v1')."
                                ),
                                cwe=self.cwe,
                                nist_ref=self.nist_ref
                            ))
                        elif isinstance(node.op, ast.Add):
                            # Check if parent is NOT a KDF call
                            parent = context.get_parent(node)
                            is_inside_kdf = False
                            if parent and isinstance(parent, ast.Call):
                                func_str = self._extract_call_name(parent)
                                if any(k in func_str.lower() for k in ["hkdf", "kdf", "derive"]):
                                    is_inside_kdf = True

                            # If naive concatenation assigned directly to key
                            if not is_inside_kdf:
                                if isinstance(parent, ast.Assign):
                                    for t in parent.targets:
                                        if isinstance(t, ast.Name) and any(k in t.id.lower() for k in ["key", "secret", "session", "hybrid"]):
                                            flagged_lines.add(node.lineno)
                                            findings.append(Finding(
                                                rule_id=self.rule_id,
                                                type="INSECURE_HYBRID_KDF",
                                                category=self.category,
                                                severity=Severity.HIGH,
                                                algorithm="Hybrid Key Combination",
                                                api=f"{left_name} + {right_name}",
                                                line=node.lineno,
                                                message=(
                                                    f"Raw concatenation '{left_name} + {right_name}' assigned directly as session/hybrid key. "
                                                    f"Concatenated shared secrets must be passed through an approved KDF."
                                                ),
                                                recommendation=(
                                                    f"Pass '{left_name} + {right_name}' through HKDF: "
                                                    f"derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'PQC-Hybrid').derive({left_name} + {right_name})."
                                                ),
                                                cwe=self.cwe,
                                                nist_ref=self.nist_ref
                                            ))

        return findings

    def _extract_zip_secret_operands(self, iter_node: ast.AST, context: AnalysisContext) -> Optional[Tuple[str, str]]:
        """
        If iter_node is a Call to zip(s1, s2, ...) where arguments are secret operands,
        returns (s1_name, s2_name).
        """
        if not isinstance(iter_node, ast.Call):
            return None

        func_name = ""
        if isinstance(iter_node.func, ast.Name):
            func_name = iter_node.func.id
        elif isinstance(iter_node.func, ast.Attribute):
            func_name = iter_node.func.attr

        if func_name != "zip" or len(iter_node.args) < 2:
            return None

        arg1_name = self._extract_var_name(iter_node.args[0])
        arg2_name = self._extract_var_name(iter_node.args[1])

        if not arg1_name:
            arg1_name = self._extract_call_name(iter_node.args[0])
        if not arg2_name:
            arg2_name = self._extract_call_name(iter_node.args[1])

        if self._is_secret_operand(arg1_name, context) or self._is_secret_operand(arg2_name, context):
            return (arg1_name, arg2_name)

        return None

    def _extract_var_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def _extract_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return node.func.attr
            elif isinstance(node.func, ast.Name):
                return node.func.id
        return ""

    def _is_secret_operand(self, name: str, context: AnalysisContext) -> bool:
        if not name:
            return False
        role = context.infer_key_role(ast.Name(id=name))
        if role in (KeyRole.SHARED_SECRET, KeyRole.CLASSICAL_SECRET, KeyRole.PQC_SECRET):
            return True
        lower = name.lower()
        secret_indicators = ["secret", "shared", "ecdh", "mlkem", "kyber", "pqc", "classical", "key"]
        return any(ind in lower for ind in secret_indicators)
