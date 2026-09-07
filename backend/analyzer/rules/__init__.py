from .base import BaseRule
from .pqc_key_confusion import PQCKeyConfusionRule
from .legacy_crypto import QuantumVulnerableLegacyCryptoRule
from .weak_entropy import WeakEntropyRule
from .unverified_sig import UnverifiedSignatureRule
from .hardcoded_secrets import HardcodedSecretRule
from .fips_compliance import FIPSComplianceRule
from .stateful_signatures import StatefulSignatureMisuseRule
from .insecure_hybrid import InsecureHybridKDFRule

ALL_RULES = [
    PQCKeyConfusionRule(),
    QuantumVulnerableLegacyCryptoRule(),
    WeakEntropyRule(),
    UnverifiedSignatureRule(),
    HardcodedSecretRule(),
    FIPSComplianceRule(),
    StatefulSignatureMisuseRule(),
    InsecureHybridKDFRule(),
]

__all__ = [
    "BaseRule",
    "ALL_RULES",
    "PQCKeyConfusionRule",
    "QuantumVulnerableLegacyCryptoRule",
    "WeakEntropyRule",
    "UnverifiedSignatureRule",
    "HardcodedSecretRule",
    "FIPSComplianceRule",
    "StatefulSignatureMisuseRule",
    "InsecureHybridKDFRule",
]
