import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext
from .base import BaseRule

SECRET_NAME_KEYWORDS = {
    "private_key", "secret_key", "privkey", "priv_key", "signing_key", "sk", "seed", "private"
}
SHARED_SECRET_EXCLUSIONS = {
    "shared", "classical", "pqc", "hybrid", "ecdh", "mlkem", "kyber"
}


class HardcodedSecretRule(BaseRule):
    rule_id = "PQC-SEC-005"
    name = "Hardcoded Secret Key or Seed"
    category = "Key Management"
    severity = Severity.CRITICAL
    cwe = "CWE-798"
    nist_ref = "NIST SP 800-57 Part 1"
    description = (
        "Detects hardcoded byte strings, hex literals, or static strings assigned to variables "
        "representing private/signing keys or cryptographic seeds."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check targets for secret-like names
                is_secret_var = False
                matched_target = ""

                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        # Avoid flagging public keys or shared secrets in hybrid exchange
                        if "public" in name_lower or "pub" in name_lower or "pk" == name_lower:
                            continue
                        if any(ex in name_lower for ex in SHARED_SECRET_EXCLUSIONS):
                            continue
                        if any(kw in name_lower for kw in SECRET_NAME_KEYWORDS):
                            is_secret_var = True
                            matched_target = target.id
                            break

                if is_secret_var:
                    # Check if assigned value is a literal (bytes or string)
                    val = node.value
                    if isinstance(val, ast.Constant):
                        if isinstance(val.value, (bytes, str)) and len(str(val.value)) >= 8:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                type="HARDCODED_SECRET",
                                category=self.category,
                                severity=Severity.CRITICAL,
                                algorithm="Cryptographic Secret / Seed",
                                api=f"{matched_target} = ...",
                                line=node.lineno,
                                message=(
                                    f"Hardcoded cryptographic secret detected in assignment to '{matched_target}'. "
                                    f"Committing static private keys or seeds into source code leads to catastrophic credential leakage."
                                ),
                                recommendation=(
                                    f"Never hardcode cryptographic keys or seeds in source code. "
                                    f"Load keys securely at runtime from environment variables (e.g., os.environ.get('PQC_PRIVATE_KEY')), "
                                    f"a Hardware Security Module (HSM), or a secure secret manager (e.g. AWS Secrets Manager, HashiCorp Vault)."
                                ),
                                cwe=self.cwe,
                                nist_ref=self.nist_ref
                            ))

        return findings
