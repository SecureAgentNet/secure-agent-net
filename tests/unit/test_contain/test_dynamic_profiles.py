import json
import pytest
from secureagentnet.contain.dynamic_profiles import (
    DynamicProfileCompiler,
    get_profile_compiler,
    ESSENTIAL_SYSCALLS,
)


class TestDynamicProfileCompiler:
    def test_compile_seccomp_read_file_only(self):
        caps = {"read_file": True}
        seccomp_json = DynamicProfileCompiler.compile_seccomp_profile(caps)
        profile = json.loads(seccomp_json)
        assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
        allowed = profile["syscalls"][0]["names"]
        for s in ["openat", "read", "close", "fstat"]:
            assert s in allowed
        # Network stays gated behind a network capability.
        for s in ["connect", "sendto"]:
            assert s not in allowed

    def test_compile_seccomp_network_access(self):
        caps = {"network_access": True}
        seccomp_json = DynamicProfileCompiler.compile_seccomp_profile(caps)
        profile = json.loads(seccomp_json)
        allowed = profile["syscalls"][0]["names"]
        assert "connect" in allowed
        assert "sendto" in allowed

    def test_execve_always_allowed_regardless_of_capabilities(self):
        """A container cannot start without execve, whatever the agent may do.

        These assertions previously read ``execve not in allowed`` for agents
        lacking "execute_code". That made every such sandbox unstartable: the
        runtime execs the entrypoint as its first act, so a deny-by-default
        profile without execve killed init immediately — surfacing as an
        unrelated netns bind-mount error, while the tests stayed green.

        Whether an agent may launch *further* programs is a real privilege
        decision, but it belongs in the AppArmor exec rules, which can name
        which binaries are executable. Seccomp cannot express it without also
        blocking the container's own entrypoint.
        """
        for caps in ({"read_file": True}, {"network_access": True}, {}):
            profile = json.loads(DynamicProfileCompiler.compile_seccomp_profile(caps))
            allowed = profile["syscalls"][0]["names"]
            assert "execve" in allowed, f"execve missing for caps={caps}"
            assert "execveat" in allowed, f"execveat missing for caps={caps}"

    def test_dangerous_syscalls_never_allowed(self):
        """The allowlist must stay an allowlist — escape primitives are absent."""
        profile = json.loads(DynamicProfileCompiler.compile_seccomp_profile(
            {"read_file": True, "write_file": True, "execute_code": True,
             "network_access": True}
        ))
        allowed = set(profile["syscalls"][0]["names"])
        for dangerous in ("ptrace", "mount", "umount2", "pivot_root", "chroot",
                          "unshare", "setns", "bpf", "keyctl", "add_key",
                          "init_module", "finit_module", "delete_module",
                          "kexec_load", "reboot", "perf_event_open",
                          "process_vm_readv", "process_vm_writev", "userfaultfd"):
            assert dangerous not in allowed, f"{dangerous} must stay denied"

    def test_compile_seccomp_multi_capability(self):
        caps = {"read_file": True, "write_file": True, "execute_code": True}
        seccomp_json = DynamicProfileCompiler.compile_seccomp_profile(caps)
        profile = json.loads(seccomp_json)
        allowed = profile["syscalls"][0]["names"]
        assert "execve" in allowed
        assert "write" in allowed
        assert "connect" not in allowed

    def test_compile_seccomp_wildcard_allows_all(self):
        caps = {"*": True}
        seccomp_json = DynamicProfileCompiler.compile_seccomp_profile(caps)
        profile = json.loads(seccomp_json)
        assert profile["defaultAction"] == "SCMP_ACT_ALLOW"

    def test_compile_seccomp_essentials_always_included(self):
        caps = {}
        seccomp_json = DynamicProfileCompiler.compile_seccomp_profile(caps)
        profile = json.loads(seccomp_json)
        allowed = profile["syscalls"][0]["names"]
        for s in ESSENTIAL_SYSCALLS[:5]:
            assert s in allowed, f"Essential syscall {s} missing"

    def test_compile_apparmor_profile_no_network(self):
        caps = {"read_file": True}
        profile = DynamicProfileCompiler.compile_apparmor_profile("agent-1", caps)
        assert "agent-1" in profile
        assert "deny network" in profile.lower()
        assert "deny /usr/bin/** x" in profile.lower()

    def test_compile_apparmor_profile_with_network(self):
        caps = {"network_access": True, "web_search": True}
        profile = DynamicProfileCompiler.compile_apparmor_profile("agent-net", caps)
        assert "network inet stream" in profile.lower()
        assert "deny network" not in profile.lower()

    def test_compile_apparmor_profile_with_exec(self):
        caps = {"read_file": True, "execute_code": True}
        profile = DynamicProfileCompiler.compile_apparmor_profile("agent-exec", caps)
        assert "/usr/bin/python" in profile.lower()
        assert "/bin/sh" in profile.lower()
        assert "deny /usr/bin/** x" not in profile.lower()

    def test_compile_apparmor_with_write(self):
        caps = {"write_file": True}
        profile = DynamicProfileCompiler.compile_apparmor_profile("agent-w", caps)
        assert "/tmp/ rw" in profile or "/tmp/  rw" in profile

    def test_singleton_get_compiler(self):
        c1 = get_profile_compiler()
        c2 = get_profile_compiler()
        assert c1 is c2

    def test_write_apparmor_profile_to_file(self):
        compiler = DynamicProfileCompiler()
        path = compiler.write_apparmor_profile("agent-test", {"read_file": True})
        assert path is not None
        import os
        assert os.path.exists(path)
        content = open(path).read()
        assert "agent-test" in content
        compiler.cleanup("agent-test")
        assert not os.path.exists(path)

    def test_cleanup_all(self):
        compiler = DynamicProfileCompiler()
        paths = []
        for i in range(3):
            p = compiler.write_apparmor_profile(f"agent-cleanup-{i}", {"read_file": True})
            if p:
                paths.append(p)
        import os
        compiler.cleanup()
        for p in paths:
            assert not os.path.exists(p)

    def test_get_seccomp_for_agent_returns_none_for_nonexistent(self):
        compiler = DynamicProfileCompiler()
        result = compiler.get_seccomp_for_agent("nonexistent-agent-xyz")
        assert result is None or isinstance(result, str)

    def test_empty_capabilities_produces_valid_json(self):
        seccomp_json = DynamicProfileCompiler.compile_seccomp_profile({})
        assert "SCMP_ACT_ERRNO" in seccomp_json
        assert "architectures" in seccomp_json
