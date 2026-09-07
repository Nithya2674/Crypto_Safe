import ast
from typing import List
from ..models import Finding, Severity
from ..context import AnalysisContext
from .base import BaseRule

WEAK_RNG_FUNCS = {"randint", "random", "choice", "choices", "sample", "getrandbits", "randrange", "seed"}


class WeakEntropyRule(BaseRule):
    rule_id = "PQC-RNG-003"
    name = "Cryptographically Insecure Pseudo-Random Number Generator"
    category = "Randomness & Entropy"
    severity = Severity.HIGH
    cwe = "CWE-338"
    nist_ref = "NIST SP 800-90A / FIPS 140-3"
    description = (
        "Detects use of standard library 'random' module (Mersenne Twister) for cryptographic keys, "
        "seeds, nonces, or secret values. Mersenne Twister is entirely predictable."
    )

    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            is_weak_random = False
            func_name = ""

            # Pattern: random.randint(...), random.random(...)
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "random" and func.attr in WEAK_RNG_FUNCS:
                    is_weak_random = True
                    func_name = f"random.{func.attr}"

            # Pattern: from random import randint; randint(...)
            elif isinstance(func, ast.Name) and func.id in WEAK_RNG_FUNCS:
                # Check if imported from random
                origin = context.imports.get(func.id, "")
                if "random" in origin or "random" in context.imported_modules:
                    is_weak_random = True
                    func_name = func.id

            if is_weak_random:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    type="WEAK_ENTROPY",
                    category=self.category,
                    severity=Severity.HIGH,
                    algorithm="Mersenne Twister (random)",
                    api=func_name,
                    line=node.lineno,
                    message=(
                        f"Insecure PRNG call '{func_name}()' detected. Python's 'random' module uses the Mersenne Twister algorithm, "
                        f"which is NOT cryptographically secure and can be reversed after 624 outputs to predict private keys or nonces."
                    ),
                    recommendation=(
                        "Replace with cryptographically secure random number generators: "
                        "use 'secrets.token_bytes(n)' or 'os.urandom(n)' for seeds and private keys, "
                        "and 'secrets.choice()' or 'secrets.randbelow()' for integers."
                    ),
                    cwe=self.cwe,
                    nist_ref=self.nist_ref
                ))

        return findings
