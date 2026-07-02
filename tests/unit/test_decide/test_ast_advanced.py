import pytest
from secureagentnet.decide.ast_verifier import ASTSemanticVerifier


class TestASTAdvancedObfuscation:
    def test_globals_subscript_exec(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "globals()['exec']('print(\"hacked\")')",
            "Print message",
            ["execute_code"],
        )
        assert safe is False
        assert "globals" in reason.lower() or "exec" in reason.lower()

    def test_locals_subscript_eval(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "locals()['eval'](user_input)",
            "Process input",
            ["execute_code"],
        )
        assert safe is False

    def test_getattr_import(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "m = getattr(__builtins__, '__import__')('os'); m.system('whoami')",
            "Import module",
            ["execute_code"],
        )
        assert safe is False

    def test_dunder_import_dynamic(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "os = __import__('os'); os.system('ls')",
            "List files",
            ["read_file"],
        )
        assert safe is False
        assert "os" in reason.lower() or "import" in reason.lower() or "system" in reason.lower()

    def test_importlib_import_module(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import importlib; sub = importlib.import_module('subprocess'); sub.run(['ls'])",
            "Run command",
            ["read_file"],
        )
        assert safe is False

    def test_getattr_direct_exec(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "getattr(globals(), 'exec')(code)",
            "Execute code",
            ["execute_code"],
        )
        assert safe is False
        assert "getattr" in reason.lower() or "exec" in reason.lower()

    def test_vars_subscript_compile(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "vars()['compile'](code, '<string>', 'exec')",
            "Compile code",
            ["execute_code"],
        )
        assert safe is False

    def test_legitimate_getattr_not_blocked(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "class X: pass; getattr(X, 'name', 'default')",
            "Get attribute",
            ["execute_code"],
        )
        assert safe is True

    def test_legitimate_globals_not_blocked(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "val = globals().get('CONFIG', {}); print(val)",
            "Read config",
            ["execute_code"],
        )
        assert safe is True
