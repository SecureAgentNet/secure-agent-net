import pytest
from secureagentnet.decide.ast_verifier import ASTSemanticVerifier


class TestASTSemanticVerifier:
    def test_safe_code(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "print('hello world')\nx = 5 + 3",
            "Print greeting",
            ["execute_code"],
        )
        assert safe is True
        assert risk < 0.3

    def test_forbidden_network_import(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import requests\nr = requests.get('http://evil.com')",
            "Read file",
            ["read_file"],
        )
        assert safe is False
        assert risk >= 0.3
        assert "requests" in reason.lower()

    def test_eval_detected(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "eval(user_input)",
            "Calculate sum",
            ["execute_code"],
        )
        assert safe is False
        assert risk >= 0.4
        assert "eval" in reason.lower()

    def test_base64_obfuscation_detected(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import base64\ndata = base64.b64decode(s)\nexec(data)",
            "Process data",
            ["execute_code"],
        )
        assert safe is False
        assert risk >= 0.3

    def test_normal_imports_ok(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import json\nimport os.path\nprint(os.path.join('a','b'))",
            "Join file paths",
            ["execute_code", "read_file"],
        )
        assert safe is True

    def test_empty_code_safe(self):
        safe, risk, _ = ASTSemanticVerifier.verify("", "", [])
        assert safe is True
        assert risk == 0.0

    def test_network_ok_when_cap_present(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import requests\nr = requests.get('https://api.example.com')",
            "Fetch data from API",
            ["network_access", "web_search"],
        )
        assert safe is True

    def test_child_import_detected(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "from urllib.request import urlopen\nurlopen('http://evil.com')",
            "Test",
            ["read_file"],
        )
        assert safe is False
        assert "urllib" in reason.lower()

    def test_subprocess_detected(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import subprocess\nsubprocess.run(['cat', '/etc/shadow'])",
            "Read config",
            ["read_file"],
        )
        assert safe is False
        assert "subprocess" in reason.lower()

    def test_subprocess_ok_with_execute_code_cap(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import subprocess\nsubprocess.run(['ls'])",
            "Run command to list directory",
            ["execute_code"],
        )
        assert safe is True

    def test_dash_import_detected(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import os\nos.system('whoami')",
            "Check system",
            ["read_file"],
        )
        assert safe is False
        # Should flag either subprocess or os or dangerous call
        assert "os" in reason.lower() or "subprocess" in reason.lower() or "system" in reason.lower()

    def test_network_intent_not_declared(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "requests.get('http://api.example.com')",
            "Read local file",
            ["network_access"],
        )
        assert safe is True

    def test_admin_wildcard_bypasses_all(self):
        safe, risk, reason = ASTSemanticVerifier.verify(
            "import requests\nimport subprocess\neval('code')",
            "Anything",
            ["admin"],
        )
        assert safe is True
