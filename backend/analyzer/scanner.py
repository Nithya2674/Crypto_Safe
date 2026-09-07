"""
CryptoAPI-Safe Scanner Public Interface.
Provides backwards-compatible functions while delegating to the modular RuleEngine.
"""

from typing import List, Dict, Any, Union
from .engine import RuleEngine
from .fixer import CodeFixer

_default_engine = RuleEngine()
_default_fixer = CodeFixer()


def scan_code(code: str) -> List[Dict[str, Any]]:
    """
    Scans Python source code using the modular RuleEngine.
    Returns list of finding dictionaries for full backwards compatibility.
    """
    result = _default_engine.analyze(code)
    return result.get("findings", [])


def scan_code_full(code: str) -> Dict[str, Any]:
    """
    Scans Python source code and returns the complete analysis payload,
    including findings, quantum readiness score, grade, and CBOM.
    """
    return _default_engine.analyze(code)


def get_registered_rules() -> List[Dict[str, Any]]:
    """Returns metadata for all active rules."""
    return _default_engine.get_registered_rules()


def auto_fix_code(code: str) -> Dict[str, Any]:
    """
    Analyzes and applies automated remediation to the provided code,
    generating a compliant version and unified diff.
    """
    return _default_fixer.fix(code)