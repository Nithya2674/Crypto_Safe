from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    type: str
    category: str
    severity: Severity
    message: str
    recommendation: str
    line: int
    algorithm: Optional[str] = None
    api: Optional[str] = None
    cwe: Optional[str] = None
    nist_ref: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "rule_id": self.rule_id,
            "type": self.type,
            "category": self.category,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "algorithm": self.algorithm or "Generic",
            "api": self.api or "Unknown",
            "line": self.line,
            "message": self.message,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "nist_ref": self.nist_ref,
        }
        if self.extra:
            result["extra"] = self.extra
        return result
