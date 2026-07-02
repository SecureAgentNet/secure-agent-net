import json
import pytest
from unittest.mock import patch, MagicMock, mock_open
from secureagentnet.contain.security_profiles import (
    SeccompProfileManager,
    AppArmorProfileManager,
    SECCOMP_DEFAULT,
    APPARMOR_DEFAULT,
)


class TestSeccompProfileManager:
    def test_load_seccomp_profile(self):
        with patch("builtins.open", mock_open(read_data=json.dumps(SECCOMP_DEFAULT))):
            with patch("pathlib.Path.exists", return_value=True):
                manager = SeccompProfileManager()
                profile = manager.load_profile()
                assert profile is not None
                parsed = json.loads(profile)
                assert parsed["defaultAction"] == "SCMP_ACT_ERRNO"

    def test_load_seccomp_profile_file_not_found(self):
        with patch("pathlib.Path.open", side_effect=FileNotFoundError):
            with patch("pathlib.Path.exists", return_value=False):
                manager = SeccompProfileManager()
                profile = manager.load_profile()
                assert profile is not None
                parsed = json.loads(profile)
                assert parsed["defaultAction"] == "SCMP_ACT_ERRNO"
                assert "SCMP_ARCH_X86_64" in parsed["architectures"]

    def test_load_seccomp_profile_uses_fallback_on_error(self):
        with patch.object(SeccompProfileManager, "load_profile", wraps=SeccompProfileManager().load_profile) as mock_load:
            manager = SeccompProfileManager()
            with patch("builtins.open", side_effect=FileNotFoundError):
                profile = manager.load_profile()
                assert profile is not None
                assert json.loads(profile) == SECCOMP_DEFAULT

    def test_get_profile_dict(self):
        with patch("builtins.open", mock_open(read_data=json.dumps(SECCOMP_DEFAULT))):
            with patch("pathlib.Path.exists", return_value=True):
                manager = SeccompProfileManager()
                profile_dict = manager.get_profile_dict()
                assert profile_dict["defaultAction"] == "SCMP_ACT_ERRNO"
                assert len(profile_dict["syscalls"]) == 2

    def test_get_profile_dict_fallback(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            manager = SeccompProfileManager()
            profile_dict = manager.get_profile_dict()
            assert profile_dict == SECCOMP_DEFAULT


class TestAppArmorProfileManager:
    def test_get_apparmor_profile(self):
        profile = AppArmorProfileManager.get_profile()
        assert profile is not None
        assert isinstance(profile, str)
        assert "profile securenet-agent" in profile
        assert "#include <tunables/global>" in profile

    def test_get_apparmor_profile_denies_sensitive_paths(self):
        profile = AppArmorProfileManager.get_profile()
        assert "deny /etc/shadow rwx" in profile
        assert "deny /root/** rwx" in profile
        assert "deny capability *," in profile

    def test_get_apparmor_profile_allows_network(self):
        profile = AppArmorProfileManager.get_profile()
        assert "network inet tcp" in profile

    def test_write_apparmor_profile(self, tmp_path):
        test_path = tmp_path / "test_apparmor"
        result = AppArmorProfileManager.write_profile(test_path)
        assert result is True
        content = test_path.read_text()
        assert "profile securenet-agent" in content
        assert "deny /etc/shadow rwx" in content

    def test_write_apparmor_profile_failure(self):
        with patch("pathlib.Path.write_text", side_effect=PermissionError("Permission denied")):
            from unittest.mock import MagicMock
            mock_path = MagicMock()
            mock_path.write_text.side_effect = PermissionError("Permission denied")
            result = AppArmorProfileManager.write_profile(mock_path)
            assert result is False
