import ast
from typing import Dict, Set, List, Optional, Any


class KeyRole:
    PUBLIC_KEY = "PUBLIC_KEY"
    PRIVATE_KEY = "PRIVATE_KEY"
    SHARED_SECRET = "SHARED_SECRET"
    CLASSICAL_SECRET = "CLASSICAL_SECRET"
    PQC_SECRET = "PQC_SECRET"
    CIPHERTEXT = "CIPHERTEXT"
    RANDOM_SEED = "RANDOM_SEED"
    SIGNATURE = "SIGNATURE"
    MESSAGE = "MESSAGE"


class AnalysisContext:
    """
    Tracks semantic context across the AST:
    - Symbol table (variable names mapped to their inferred cryptographic roles)
    - Imported modules and aliases
    - Active cryptographic algorithms in scope
    - Parent map for AST nodes (e.g. to inspect if a call is in an If/Assert vs bare Expr)
    """

    def __init__(self, tree: ast.AST, source_code: str = ""):
        self.tree = tree
        self.source_code = source_code
        self.lines = source_code.splitlines() if source_code else []
        self.symbols: Dict[str, str] = {}  # var_name -> KeyRole
        self.imports: Dict[str, str] = {}  # imported_name -> original_module
        self.imported_modules: Set[str] = set()
        self.parent_map: Dict[ast.AST, ast.AST] = {}
        self.detected_algorithms: Set[str] = set()

        self._build_parent_map(tree)
        self._analyze_imports(tree)
        self._build_symbol_table(tree)

    def _build_parent_map(self, tree: ast.AST):
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                self.parent_map[child] = parent

    def get_parent(self, node: ast.AST) -> Optional[ast.AST]:
        return self.parent_map.get(node)

    def _analyze_imports(self, tree: ast.AST):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = alias.name
                    self.imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                self.imported_modules.add(module.split(".")[0])
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.imports[name] = f"{module}.{alias.name}"

    def _build_symbol_table(self, tree: ast.AST):
        """
        Infers variable roles from assignments and method calls:
        e.g.
          pk = signer.generate_keypair()  --> pk is PUBLIC_KEY
          sk = signer.export_secret_key() --> sk is PRIVATE_KEY
          ciphertext, shared_secret = ... --> ciphertext, shared_secret roles
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._handle_assign(node)

    def _handle_assign(self, node: ast.Assign):
        # Check RHS of assignment
        rhs = node.value

        # Pattern: var = signer.generate_keypair()
        # In liboqs Python: generate_keypair() generates a pair and returns public_key bytes!
        if isinstance(rhs, ast.Call) and isinstance(rhs.func, ast.Attribute):
            method = rhs.func.attr
            if method == "generate_keypair":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.symbols[target.id] = KeyRole.PUBLIC_KEY
            elif method in ("export_secret_key", "get_secret_key", "export_private_key"):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.symbols[target.id] = KeyRole.PRIVATE_KEY
            elif method == "encap_secret":
                # Returns (ciphertext, shared_secret)
                for target in node.targets:
                    if isinstance(target, ast.Tuple) and len(target.elts) == 2:
                        if isinstance(target.elts[0], ast.Name):
                            self.symbols[target.elts[0].id] = KeyRole.CIPHERTEXT
                        if isinstance(target.elts[1], ast.Name):
                            self.symbols[target.elts[1].id] = KeyRole.SHARED_SECRET
            elif method == "decap_secret":
                # Returns shared_secret
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.symbols[target.id] = KeyRole.SHARED_SECRET
            elif method == "sign":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.symbols[target.id] = KeyRole.SIGNATURE

        # Heuristic fallback by variable naming if not already identified
        for target in node.targets:
            if isinstance(target, ast.Name):
                name_lower = target.id.lower()
                if target.id not in self.symbols:
                    if any(pub in name_lower for pub in ["public", "pub_key", "pubkey", "pk"]):
                        self.symbols[target.id] = KeyRole.PUBLIC_KEY
                    elif any(priv in name_lower for priv in ["private", "priv_key", "privkey", "secret_key", "sk"]):
                        self.symbols[target.id] = KeyRole.PRIVATE_KEY
                    elif any(c in name_lower for c in ["classical", "ecdh", "x25519", "trad"]):
                        self.symbols[target.id] = KeyRole.CLASSICAL_SECRET
                    elif any(p in name_lower for p in ["pqc", "mlkem", "kyber"]):
                        self.symbols[target.id] = KeyRole.PQC_SECRET
                    elif any(s in name_lower for s in ["shared_secret", "secret", "shared_key"]):
                        self.symbols[target.id] = KeyRole.SHARED_SECRET
                    elif any(ct in name_lower for ct in ["ciphertext", "cipher_text", "ct"]):
                        self.symbols[target.id] = KeyRole.CIPHERTEXT
                    elif any(sig in name_lower for sig in ["signature", "sig"]):
                        self.symbols[target.id] = KeyRole.SIGNATURE

    def infer_key_role(self, expr: ast.AST) -> Optional[str]:
        """Returns the inferred key role of an AST expression, if identifiable."""
        if isinstance(expr, ast.Name):
            # Check symbol table
            if expr.id in self.symbols:
                return self.symbols[expr.id]
            name_lower = expr.id.lower()
            if any(p in name_lower for p in ["public", "pub_key", "pubkey", "pk"]):
                return KeyRole.PUBLIC_KEY
            if any(p in name_lower for p in ["private", "priv_key", "privkey", "secret_key", "sk"]):
                return KeyRole.PRIVATE_KEY
            if any(c in name_lower for c in ["classical", "ecdh", "x25519", "trad"]):
                return KeyRole.CLASSICAL_SECRET
            if any(p in name_lower for p in ["pqc", "mlkem", "kyber"]):
                return KeyRole.PQC_SECRET
            if any(s in name_lower for s in ["shared_secret", "shared_key"]):
                return KeyRole.SHARED_SECRET
            if any(c in name_lower for c in ["ciphertext", "ct"]):
                return KeyRole.CIPHERTEXT
        return None
