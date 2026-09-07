import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext, KeyRole
from .base import BaseRule


class PQCKeyConfusionRule(BaseRule):
    rule_id = "PQC-KEY-001"
    name = "PQC Key Role Confusion"
    category = "Key Management"
    severity = Severity.HIGH
    cwe = "CWE-327"
    nist_ref = "NIST FIPS 203 / FIPS 204"
    description = (
        "Detects passing a public key to signing/decapsulation APIs, or a "
        "private key to verification/encapsulation APIs."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Attribute):
                continue

            func_name = node.func.attr

            # 1. Detect ML-DSA / Signature sign() misuse
            if func_name == "sign":
                # In liboqs: sign(message) takes only message.
                # If user passes 2 args e.g. sign(message, public_key) or sign(message, pk)
                if len(node.args) >= 2:
                    key_arg = node.args[1]
                    role = context.infer_key_role(key_arg)
                    if role == KeyRole.PUBLIC_KEY:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="WRONG_KEY_USAGE",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm="ML-DSA",
                            api="sign",
                            line=node.lineno,
                            message="Public key passed to ML-DSA signing API. Signing mathematically requires the private/signing key.",
                            recommendation="Remove the public key argument or pass the private key. In liboqs, signer.sign(message) uses the instance's private key directly.",
                            cwe=self.cwe,
                            nist_ref="NIST FIPS 204"
                        ))

            # 2. Detect Signature verify() misuse
            elif func_name == "verify":
                # liboqs verify(message, signature, public_key)
                if len(node.args) >= 3:
                    key_arg = node.args[2]
                    role = context.infer_key_role(key_arg)
                    if role == KeyRole.PRIVATE_KEY:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="WRONG_KEY_USAGE",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm="ML-DSA",
                            api="verify",
                            line=node.lineno,
                            message="Private key passed to signature verification API. Verification must only use the public key.",
                            recommendation="Pass the sender's public key to verify() instead of the private/secret key.",
                            cwe=self.cwe,
                            nist_ref="NIST FIPS 204"
                        ))

            # 3. Detect KEM encap_secret() misuse
            elif func_name == "encap_secret":
                # encap_secret(public_key)
                if len(node.args) >= 1:
                    key_arg = node.args[0]
                    role = context.infer_key_role(key_arg)
                    if role == KeyRole.PRIVATE_KEY:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="WRONG_KEY_USAGE",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm="ML-KEM",
                            api="encap_secret",
                            line=node.lineno,
                            message="Private key passed to KEM encapsulation API. Encapsulation must use the recipient's public key.",
                            recommendation="Pass the recipient's public key to encap_secret() to generate the shared secret and ciphertext.",
                            cwe=self.cwe,
                            nist_ref="NIST FIPS 203"
                        ))

            # 4. Detect KEM decap_secret() misuse
            elif func_name == "decap_secret":
                # decap_secret(ciphertext, [optional key in some libraries])
                if len(node.args) >= 2:
                    key_arg = node.args[1]
                    role = context.infer_key_role(key_arg)
                    if role == KeyRole.PUBLIC_KEY:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            type="WRONG_KEY_USAGE",
                            category=self.category,
                            severity=Severity.HIGH,
                            algorithm="ML-KEM",
                            api="decap_secret",
                            line=node.lineno,
                            message="Public key passed to KEM decapsulation API. Decapsulation requires the recipient's private key.",
                            recommendation="Use the private/secret key to decapsulate the shared secret from the ciphertext.",
                            cwe=self.cwe,
                            nist_ref="NIST FIPS 203"
                        ))

        return findings
