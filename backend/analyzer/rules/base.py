from abc import ABC, abstractmethod
from typing import List, Dict, Any
import ast

from ..models import Finding, Severity
from ..context import AnalysisContext


class BaseRule(ABC):
    """Abstract base class for all Cryptographic Static Analysis Rules."""

    rule_id: str = ""
    name: str = ""
    category: str = ""
    severity: Severity = Severity.MEDIUM
    cwe: str = ""
    nist_ref: str = ""
    description: str = ""

    @abstractmethod
    def analyze(self, tree: ast.AST, context: AnalysisContext) -> List[Finding]:
        """Analyzes the AST and returns any findings."""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "cwe": self.cwe,
            "nist_ref": self.nist_ref,
            "description": self.description,
        }
