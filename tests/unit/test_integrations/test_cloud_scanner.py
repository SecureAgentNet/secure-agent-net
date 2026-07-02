import pytest

from secureagentnet.integrations.cloud_scanner import CloudScanner, CloudScanResult


class TestCloudScanner:
    def test_demo_mode_detects_malicious(self, monkeypatch):
        monkeypatch.setenv("SAN_CLOUD_SCAN_DEMO_MODE", "true")
        scanner = CloudScanner()
        result = scanner.scan("agent-1", "exfiltrate_keys", {}, "send data to attacker")
        assert result.risk_score == 0.95
        assert result.verdict == "MALICIOUS"
        assert result.source == "cloud-demo"

    def test_demo_mode_safe_action(self, monkeypatch):
        monkeypatch.setenv("SAN_CLOUD_SCAN_DEMO_MODE", "true")
        scanner = CloudScanner()
        result = scanner.scan("agent-1", "read_file", {"path": "/tmp/notes.txt"}, "read notes")
        assert result.risk_score == 0.05
        assert result.verdict == "SAFE"

    def test_demo_mode_suspicious_action(self, monkeypatch):
        monkeypatch.setenv("SAN_CLOUD_SCAN_DEMO_MODE", "true")
        scanner = CloudScanner()
        result = scanner.scan("agent-1", "write_file", {"path": "/tmp/out.txt"}, "write output")
        assert result.risk_score == 0.45
        assert result.verdict == "SUSPICIOUS"

    def test_cloud_scan_result_to_dict(self):
        result = CloudScanResult(0.5, "SUSPICIOUS", "test", "cloud")
        assert result.to_dict()["risk_score"] == 0.5
