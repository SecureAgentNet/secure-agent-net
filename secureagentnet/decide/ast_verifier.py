import ast
import logging
from typing import Dict, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)

NETWORK_IMPORTS = {"urllib", "urllib2", "urllib3", "requests", "http", "socket", "http.client", "httpx", "aiohttp", "websockets", "ftplib", "telnetlib", "smtplib"}
SUBPROCESS_IMPORTS = {"subprocess", "os.system", "popen", "pexpect", "sh"}
FILE_SYSTEM_IMPORTS = {"os", "pathlib", "io", "shutil", "glob"}
EVAL_IMPORTS = {"eval", "exec", "compile", "__import__", "importlib", "__builtins__"}


class ASTSemanticVerifier:
    """Evaluates code for semantic drift by analyzing the Abstract Syntax Tree.

    Scans Python code for:
    - Suspicious imports beyond declared capabilities
    - Inline eval/exec patterns
    - Hidden subprocess calls
    - Network socket creation
    - Base64/encoding obfuscation patterns
    """

    @classmethod
    def verify(
        cls,
        code: str,
        declared_intent: str = "",
        allowed_capabilities: Optional[List[str]] = None,
    ) -> Tuple[bool, float, str]:
        """Analyze code AST and return (safe, risk_score, reason)."""
        if not code or not code.strip():
            return True, 0.0, "Empty code"

        capabilities = allowed_capabilities or []
        if cls._check_allow_all(capabilities):
            return True, 0.0, "Admin/wildcard capability — all operations allowed"

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return True, 0.3, f"Code has syntax issues (not necessarily malicious): {e}"

        risk_score = 0.0
        reasons: List[str] = []

        imports = cls._extract_imports(tree)
        dynamic_imports = cls._extract_dynamic_imports(tree)
        all_imports = imports | dynamic_imports
        calls = cls._extract_calls(tree)
        attempts = cls._extract_eval_attempts(tree)

        forbidden_imports = cls._check_imports(all_imports, allowed_capabilities or [])
        if forbidden_imports:
            risk_score += 0.4
            reasons.append(f"Forbidden imports: {', '.join(forbidden_imports)}")

        if attempts:
            risk_score += 0.4
            reasons.append(f"Eval/exec/inline-compile detected: {', '.join(attempts[:3])}")

        obfuscation = cls._detect_obfuscation(code)
        if obfuscation:
            risk_score += 0.3
            reasons.append(f"Obfuscation detected: {', '.join(obfuscation)}")

        if risk_score == 0.0 and cls._has_dangerous_calls(calls, allowed_capabilities or []):
            risk_score += 0.15

        intent_violation = cls._check_intent_match(code, declared_intent, allowed_capabilities or [])
        if intent_violation:
            risk_score += 0.2
            reasons.append(intent_violation)

        safe = risk_score < 0.4
        reason = "; ".join(reasons) if reasons else "Code appears safe"
        return safe, min(risk_score, 1.0), reason

    @classmethod
    def _extract_imports(cls, tree: ast.AST) -> Set[str]:
        imports: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        return imports

    @classmethod
    def _extract_calls(cls, tree: ast.AST) -> Set[str]:
        calls: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    calls.add(node.func.attr)
        return calls

    @classmethod
    def _extract_eval_attempts(cls, tree: ast.AST) -> List[str]:
        attempts: List[str] = []
        EVAL_NAMES = {"eval", "exec", "compile", "__import__"}
        BUILTIN_CALLABLES = {"globals", "locals", "vars", "__builtins__", "builtins"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Direct: eval(), exec(), compile()
                if isinstance(node.func, ast.Name) and node.func.id in EVAL_NAMES:
                    attempts.append(f"{node.func.id}() on line {node.lineno}")

                # Subscript call: globals()['exec'](...), vars()['eval'](...)
                elif isinstance(node.func, ast.Subscript):
                    sub = node.func
                    callee = None
                    if isinstance(sub.value, ast.Call) and isinstance(sub.value.func, ast.Name):
                        callee = sub.value.func.id
                    elif isinstance(sub.value, ast.Name):
                        callee = sub.value.id
                    if callee in BUILTIN_CALLABLES:
                        if isinstance(sub.slice, ast.Constant) and sub.slice.value in EVAL_NAMES:
                            attempts.append(f"{callee}()['{sub.slice.value}'] on line {node.lineno}")

                # Attribute: globals().exec(...), builtins.__import__(...)
                elif isinstance(node.func, ast.Attribute):
                    if node.func.attr in EVAL_NAMES:
                        if isinstance(node.func.value, ast.Call):
                            callee2 = node.func.value
                            if isinstance(callee2.func, ast.Name) and callee2.func.id in BUILTIN_CALLABLES:
                                attempts.append(f"{callee2.func.id}().{node.func.attr}() on line {node.lineno}")

                    # Subscript then attribute: globals()['builtins'].exec
                    elif isinstance(node.func.value, ast.Subscript):
                        pass  # handled above

                # getattr(x, 'exec')(...) or getattr(globals(), 'exec')(...)
                elif isinstance(node.func, ast.Call) and isinstance(node.func.func, ast.Name) and node.func.func.id == "getattr":
                    if len(node.func.args) >= 2:
                        arg1 = node.func.args[1]
                        if isinstance(arg1, ast.Constant) and arg1.value in EVAL_NAMES:
                            attempts.append(f"getattr(..., '{arg1.value}') on line {node.lineno}")

        return attempts

    @classmethod
    def _extract_dynamic_imports(cls, tree: ast.AST) -> Set[str]:
        dynamic: Set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # importlib.import_module("os")
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("import_module",):
                        if node.args and isinstance(node.args[0], ast.Constant):
                            dynamic.add(str(node.args[0].value).split(".")[0])
                    # Possibly imported as: subprocess = importlib.import_module(...)
                    # Need to track variable assignments too

                # __import__("os")
                elif isinstance(node.func, ast.Name) and node.func.id == "__import__":
                    if node.args and isinstance(node.args[0], ast.Constant):
                        dynamic.add(str(node.args[0].value).split(".")[0])

            # Track variable assignments that receive dynamic imports
            # e.g., os = __import__("os") or sub = importlib.import_module("subprocess")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(node.value, ast.Call):
                        func = node.value.func
                        if isinstance(func, ast.Name) and func.id == "__import__":
                            if node.value.args and isinstance(node.value.args[0], ast.Constant):
                                dynamic.add(str(node.value.args[0].value).split(".")[0])
                        elif isinstance(func, ast.Attribute) and func.attr == "import_module":
                            if node.value.args and isinstance(node.value.args[0], ast.Constant):
                                dynamic.add(str(node.value.args[0].value).split(".")[0])

        return dynamic

    @classmethod
    def _check_imports(cls, imports: Set[str], capabilities: List[str]) -> List[str]:
        if cls._check_allow_all(capabilities):
            return []

        forbidden: List[str] = []
        has_network = any(c in capabilities for c in ("network_access", "web_search", "dns_resolve"))
        has_exec = any(c in capabilities for c in ("execute_code",))
        has_fs_write = any(c in capabilities for c in ("write_file",))

        if not has_network:
            bad_net = imports & NETWORK_IMPORTS
            if bad_net:
                forbidden.extend(sorted(bad_net))

        if not has_exec:
            bad_sub = imports & SUBPROCESS_IMPORTS
            if bad_sub:
                forbidden.extend(sorted(bad_sub))
            if "os" in imports:
                forbidden.append("os")
            if "pathlib" in imports and not has_fs_write and "shutil" in imports:
                forbidden.append("shutil")

        if not has_fs_write and not has_exec:
            bad_fs = imports & FILE_SYSTEM_IMPORTS
            bad_fs -= {"os", "pathlib"}
            if bad_fs:
                forbidden.extend(sorted(bad_fs))

        return forbidden

    @classmethod
    def _has_dangerous_calls(cls, calls: Set[str], capabilities: List[str]) -> bool:
        if "*" in capabilities or "admin" in capabilities:
            return False
        dangerous = {"open", "system", "popen", "exec", "eval"}
        found = dangerous & calls
        return bool(found)

    @classmethod
    def _check_allow_all(cls, capabilities: List[str]) -> bool:
        return "*" in capabilities or "admin" in capabilities

    @classmethod
    def _detect_obfuscation(cls, code: str) -> List[str]:
        patterns: List[str] = []
        lower = code.lower()

        if "base64" in lower and ("decode" in lower or "b64decode" in lower):
            patterns.append("base64_decode")
        if "exec(" in lower and ("chr(" in lower or "ord(" in lower):
            patterns.append("exec_chr_obfuscation")
        if "__import__" in lower:
            patterns.append("dunder_import")
        if "getattr(" in lower and "__" in lower:
            patterns.append("getattr_dunder")
        return patterns

    @classmethod
    def _check_intent_match(cls, code: str, declared_intent: str, capabilities: List[str]) -> str:
        """Check if the code's operations match the declared intent."""
        if not declared_intent:
            return ""
        lower_intent = declared_intent.lower()
        lower_code = code.lower()

        network_ops = {"requests.", "urllib", "socket.", "http.client", "curl", "wget"}
        file_ops = {"open(", "read(", "write(", "delete", "remove(", "rm "}
        sub_ops = {"subprocess", "os.system", "os.popen"}

        if any(op in lower_code for op in network_ops):
            if "network" not in lower_intent and "web" not in lower_intent and "search" not in lower_intent and "fetch" not in lower_intent and "api" not in lower_intent:
                return "Network operation not declared in intent"
        if any(op in lower_code for op in sub_ops):
            if "execute" not in lower_intent and "run" not in lower_intent and "command" not in lower_intent:
                return "Subprocess/execution not declared in intent"
        return ""
