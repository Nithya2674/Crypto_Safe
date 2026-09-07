import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext
from .base import BaseRule

STATEFUL_SCHEMES = {"lms", "hss", "xmss", "xmssmt", "xmss-sha2", "lms-sha256"}


class StatefulSignatureMisuseRule(BaseRule):
    rule_id = "PQC-SIG-007"
    name = "Stateful Hash-Based Signature Risk"
    category = "Signature Security"
    severity = Severity.HIGH
    cwe = "CWE-327"
    nist_ref = "NIST SP 800-208"
    description = (
        "Detects usage of stateful hash-based signatures (LMS, HSS, XMSS). "
        "Stateful signatures require atomic non-volatile state synchronization; "
        "reusing an OTS leaf key completely breaks the private key."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []
        flagged_lines = set()

        for node in ast.walk(tree):
            # Check string algorithm literals or function/class names
            target_str = ""
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                target_str = node.value.strip().lower()
            elif isinstance(node, ast.Name):
                target_str = node.id.lower()
            elif isinstance(node, ast.Attribute):
                target_str = node.attr.lower()

            for scheme in STATEFUL_SCHEMES:
                if (scheme == target_str or scheme in target_str) and node.lineno not in flagged_lines:
                    flagged_lines.add(node.lineno)
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        type="STATEFUL_SIG_REUSE",
                        category=self.category,
                        severity=Severity.HIGH,
                        algorithm=scheme.upper(),
                        api=target_str,
                        line=node.lineno,
                        message=(
                            f"Stateful hash-based signature primitive '{scheme.upper()}' detected. "
                            f"Stateful schemes (NIST SP 800-208) maintain a strictly monotonic state counter. "
                            f"If state rollback, VM snapshot restore, or multi-process concurrency causes an OTS key to be used twice, "
                            f"an attacker can forge arbitrary signatures and extract the private key."
                        ),
                        recommendation=(
                            "If stateless operation is required, prefer NIST FIPS 204 (ML-DSA) or NIST FIPS 205 (SLH-DSA). "
                            "If stateful signatures are mandatory (e.g. firmware signing), enforce hardware-backed, atomic, "
                            "non-volatile state storage compliant with NIST SP 800-208."
                        ),
                        cwe=self.cwe,
                        nist_ref=self.nist_ref
                    ))

        return findings
