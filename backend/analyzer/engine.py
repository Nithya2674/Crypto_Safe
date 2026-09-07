import ast
from typing import List, Dict, Any, Optional
from .models import Finding, Severity
from .context import AnalysisContext
from .rules import ALL_RULES, BaseRule


class RuleEngine:
    """
    Core static analysis engine that parses Python AST,
    builds semantic context, executes all registered rules,
    and calculates Quantum Readiness Score and CBOM.
    """

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules: List[BaseRule] = rules if rules is not None else list(ALL_RULES)

    def analyze(self, code: str) -> Dict[str, Any]:
        """
        Runs full AST analysis on code string.
        Returns dictionary with findings, summary, quantum readiness score, and CBOM.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError as error:
            syntax_finding = Finding(
                rule_id="SYNTAX-000",
                type="SYNTAX_ERROR",
                category="Code Syntax",
                severity=Severity.HIGH,
                line=error.lineno or 1,
                message=f"Python SyntaxError: {error.msg}",
                recommendation="Fix Python syntax error before cryptographic analysis.",
                algorithm="N/A",
                api="ast.parse",
            )
            return {
                "success": False,
                "findings": [syntax_finding.to_dict()],
                "total_findings": 1,
                "readiness_score": 0,
                "grade": "F",
                "cbom": [],
                "summary": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                },
                "error": str(error)
            }

        context = AnalysisContext(tree, code)
        findings: List[Finding] = []

        for rule in self.rules:
            try:
                rule_findings = rule.analyze(tree, context)
                findings.extend(rule_findings)
            except Exception as exc:
                # Isolate rule failure to prevent breaking the whole scanner
                print(f"[RuleEngine Error] Rule {rule.rule_id} failed: {exc}")

        # Sort findings by line number
        findings.sort(key=lambda f: f.line)

        # Calculate Quantum Readiness Score
        score, grade = self._calculate_readiness_score(findings)

        # Build Cryptographic Bill of Materials (CBOM)
        cbom = self._build_cbom(findings, context)

        return {
            "success": True,
            "findings": [f.to_dict() for f in findings],
            "total_findings": len(findings),
            "readiness_score": score,
            "grade": grade,
            "cbom": cbom,
            "summary": {
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
            }
        }

    def _calculate_readiness_score(self, findings: List[Finding]) -> tuple[int, str]:
        score = 100
        for f in findings:
            if f.severity == Severity.CRITICAL:
                score -= 30
            elif f.severity == Severity.HIGH:
                score -= 20
            elif f.severity == Severity.MEDIUM:
                score -= 10
            elif f.severity == Severity.LOW:
                score -= 5

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return score, grade

    def _build_cbom(self, findings: List[Finding], context: AnalysisContext) -> List[Dict[str, Any]]:
        cbom = []
        seen = set()

        for f in findings:
            key = (f.algorithm, f.category)
            if key not in seen and f.algorithm and f.algorithm != "N/A":
                seen.add(key)
                is_pqc = any(p in (f.algorithm or "").upper() for p in ["ML-KEM", "ML-DSA", "SLH-DSA", "FIPS"])
                cbom.append({
                    "asset": f.algorithm,
                    "category": f.category,
                    "quantum_safe": is_pqc,
                    "status": "VULNERABLE" if not is_pqc and f.severity in (Severity.HIGH, Severity.CRITICAL) else "REVIEW",
                    "cwe": f.cwe,
                    "nist_ref": f.nist_ref,
                })

        return cbom

    def get_registered_rules(self) -> List[Dict[str, Any]]:
        return [rule.get_metadata() for rule in self.rules]
