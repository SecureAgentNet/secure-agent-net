import logging
import socket
import json
import time
import os
import struct
import threading
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("SecureAgentNet.Identify.Discovery")


@dataclass
class DiscoveredAgent:
    agent_id: Optional[str]
    name: str
    source: str  # docker / mcp / process / network / filesystem
    framework: str = "unknown"
    host: str = "localhost"
    port: Optional[int] = None
    container_id: Optional[str] = None
    pid: Optional[int] = None
    config_path: Optional[str] = None
    capabilities: list[str] = field(default_factory=list)
    status: str = "discovered"
    discovered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class BaseScanner(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self) -> list[DiscoveredAgent]:
        ...



#  1. DOCKER SOCKET SCANNER

class DockerSocketScanner(BaseScanner):
    name = "docker"

    AI_AGENT_LABELS = {
        "ai.agent": "",
        "ai.agent.framework": "",
        "san.agent": "",
        "mcp.enabled": "",
        "langchain": "",
        "autogen": "",
        "crewai": "",
        "agent.framework": "",
        "com.docker.compose.service": "",
    }

    FRAMEWORK_SIGNATURES = {
        "langchain": ["langchain", "langgraph"],
        "autogen": ["autogen", "pyautogen"],
        "crewai": ["crewai", "crew-ai"],
        "custom": [],
    }

    def scan(self) -> list[DiscoveredAgent]:
        try:
            import docker
        except ImportError:
            logger.debug("docker SDK not installed, trying docker CLI")
            return self._scan_via_cli()

        try:
            client = docker.from_env(timeout=5)
            containers = client.containers.list(all=True)
        except Exception as exc:
            logger.debug("Docker daemon not reachable: %s", exc)
            return self._scan_via_cli()

        results: list[DiscoveredAgent] = []
        for container in containers:
            agent = self._inspect_container(container)
            if agent:
                results.append(agent)
        return results

    def _scan_via_cli(self) -> list[DiscoveredAgent]:
        import subprocess

        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{json .}}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return []

        results: list[DiscoveredAgent] = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                container = json.loads(line)
            except json.JSONDecodeError:
                continue
            agent = self._parse_cli_container(container)
            if agent:
                results.append(agent)
        return results

    def _inspect_container(self, container) -> Optional[DiscoveredAgent]:
        labels = container.labels or {}
        image_name = (container.image.tags[0] if container.image.tags else container.image.short_id)
        envs = {env.split("=", 1)[0]: env.split("=", 1)[1] for env in container.attrs.get("Config", {}).get("Env", []) if "=" in env}

        framework = self._detect_framework(container.name, labels, envs, image_name)

        if not self._is_agent_candidate(labels, envs, container.name, image_name, framework):
            return None

        return DiscoveredAgent(
            agent_id=labels.get("san.agent.id"),
            name=labels.get("ai.agent.name") or labels.get("san.agent.name") or container.name,
            source="docker",
            framework=framework,
            container_id=container.short_id,
            port=self._extract_port(container.ports, envs),
            status=container.status,
            capabilities=self._infer_capabilities(labels, envs),
            extra={
                "image": image_name,
                "labels": dict(labels),
                "status_detail": container.status,
                "ports": list(container.ports.keys()) if container.ports else [],
            },
        )

    def _parse_cli_container(self, container: dict) -> Optional[DiscoveredAgent]:
        name = container.get("Names", "")
        image = container.get("Image", "")
        container_id = container.get("ID", "")
        status = container.get("State", "unknown")

        framework = self._detect_framework(name, {}, {}, image)

        if not self._is_agent_candidate({}, {}, name, image, framework):
            return None

        return DiscoveredAgent(
            agent_id=None,
            name=name.strip("/"),
            source="docker",
            framework=framework,
            container_id=container_id,
            status=status,
            extra={"image": image, "status_detail": status},
        )

    def _is_agent_candidate(self, labels: dict, envs: dict, name: str, image: str, framework: str) -> bool:
        if any(k in labels for k in self.AI_AGENT_LABELS):
            return True
        if framework != "custom":
            return True
        agent_keywords = ["agent", "mcp", "llm", "ollama", "langchain", "crew", "autogen", "bot", "assistant"]
        lower_name = name.lower()
        if any(kw in lower_name for kw in agent_keywords):
            return True
        for key_prefix in ["MCP_", "AGENT_", "SAN_", "OLLAMA_"]:
            if any(k.startswith(key_prefix) for k in envs):
                return True
        return False

    def _detect_framework(self, name: str, labels: dict, envs: dict, image: str) -> str:
        combined = (name + " " + " ".join(labels.values()) + " " + " ".join(envs.values()) + " " + image).lower()
        for fw, signatures in self.FRAMEWORK_SIGNATURES.items():
            if any(sig in combined for sig in signatures):
                return fw
        for fw, sigs in self.FRAMEWORK_SIGNATURES.items():
            for sig in sigs:
                if sig in combined:
                    return fw
        return "custom"

    def _extract_port(self, ports: dict, envs: dict) -> Optional[int]:
        if ports:
            for port_key in ports:
                if isinstance(port_key, tuple):
                    return port_key[0]
                if isinstance(port_key, str) and "/" in port_key:
                    return int(port_key.split("/")[0])
        for env_key in ("MCP_PORT", "PORT", "API_PORT", "AGENT_PORT", "SERVER_PORT"):
            val = envs.get(env_key)
            if val and val.isdigit():
                return int(val)
        return None

    def _infer_capabilities(self, labels: dict, envs: dict) -> list[str]:
        caps = set()
        cap_labels = {k: v for k, v in labels.items() if k.startswith("ai.cap.") or k.startswith("san.cap.")}
        for k in cap_labels:
            cap_name = k.rsplit(".", 1)[-1]
            if cap_name:
                caps.add(cap_name)
        env_caps = envs.get("AGENT_CAPABILITIES") or envs.get("SAN_CAPABILITIES")
        if env_caps:
            for c in env_caps.split(","):
                caps.add(c.strip())
        return sorted(caps) if caps else ["execute", "read_file", "search"]


# ────────────────────────────────────────────────────────────
#  2. MCP PORT SCANNER
#

class McpPortScanner(BaseScanner):
    name = "mcp"

    MCP_PORTS = [8443, 5000, 8080, 3000, 9001, 9090, 8444, 443]
    TIMEOUT = 2.0

    def scan(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []
        for port in self.MCP_PORTS:
            agent = self._probe_port(port)
            if agent:
                results.append(agent)
        return results

    def _probe_port(self, port: int) -> Optional[DiscoveredAgent]:
        if not self._port_open(port):
            return None

        for endpoint in ("/health", "/api/v1/auth/challenge", "/api/version", "/docs", "/"):
            try:
                import urllib.request
                import urllib.error

                url = f"http://127.0.0.1:{port}{endpoint}"
                req = urllib.request.Request(url, data=None, headers={"User-Agent": "SecureAgentNet/2.0"})
                resp = urllib.request.urlopen(req, timeout=self.TIMEOUT)

                body = resp.read().decode("utf-8", errors="replace")
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    data = {"raw": body[:200]}

                framework = self._detect_framework_from_response(data, body, resp.headers)
                name = self._extract_name(data, port)

                return DiscoveredAgent(
                    agent_id=data.get("agent_id"),
                    name=name,
                    source="mcp",
                    framework=framework,
                    host="127.0.0.1",
                    port=port,
                    status="reachable",
                    capabilities=data.get("capabilities", []),
                    extra={
                        "endpoint": endpoint,
                        "http_status": resp.status,
                        "version": data.get("version", ""),
                        "server": resp.headers.get("Server", ""),
                    },
                )
            except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, OSError):
                continue
            except Exception:
                continue
        return None

    def _port_open(self, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            return result == 0
        except OSError:
            return False

    def _detect_framework_from_response(self, data: dict, raw_body: str, headers) -> str:
        raw_lower = str(data).lower() + raw_body.lower()
        server_header = headers.get("Server", "").lower()
        combined = raw_lower + " " + server_header

        if "secureagentnet" in combined or "san" in raw_lower:
            return "secureagentnet"
        if "langchain" in combined:
            return "langchain"
        if "autogen" in combined:
            return "autogen"
        if "crewai" in combined or "crew-ai" in combined:
            return "crewai"
        if "fastapi" in server_header or "fastapi" in combined:
            return "fastapi-app"
        if "flask" in combined:
            return "flask-app"
        if "ollama" in combined:
            return "ollama"
        if "uvicorn" in server_header:
            return "uvicorn-app"
        return "unknown-http"

    def _extract_name(self, data: dict, port: int) -> str:
        for key in ("name", "agent_name", "app_name", "title", "service"):
            val = data.get(key)
            if val and isinstance(val, str):
                return val
        if data.get("version"):
            return f"mcp-service-{port}"
        return f"http-service-{port}"


#
#  3. PROCESS SCANNER
#

class ProcessScanner(BaseScanner):
    name = "process"

    FRAMEWORK_MARKERS = {
        "langchain": ["langchain", "langgraph", "langchain_core", "langchain_community"],
        "autogen": ["autogen", "pyautogen", "autogen_agentchat"],
        "crewai": ["crewai", "crew.run", "crew.kickoff"],
        "huggingface": ["transformers", "agents", "smolagents"],
        "openai-agents": ["openai.agents", "agents.run"],
        "mcp-server": ["mcp.server", "fastmcp", "mcp_gateway"],
        "llama-index": ["llama_index", "llama-index"],
        "custom": [],
    }

    PROCESS_SCAN_DIRS = ["/proc"]

    def scan(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []
        seen_pids: set[int] = set()

        for proc_dir in self.PROCESS_SCAN_DIRS:
            if not os.path.isdir(proc_dir):
                continue
            for entry in os.listdir(proc_dir):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                if pid in seen_pids:
                    continue
                seen_pids.add(pid)

                agent = self._inspect_process(proc_dir, entry, pid)
                if agent:
                    results.append(agent)

        return results

    def _inspect_process(self, proc_dir: str, entry: str, pid: int) -> Optional[DiscoveredAgent]:
        try:
            cmdline_path = os.path.join(proc_dir, entry, "cmdline")
            if not os.path.exists(cmdline_path):
                return None

            cmdline = Path(cmdline_path).read_bytes().decode("utf-8", errors="replace")
            cmdline_clean = cmdline.replace("\x00", " ").strip()
            if not cmdline_clean:
                return None

            framework = self._match_framework(cmdline_clean)

            environ_path = os.path.join(proc_dir, entry, "environ")
            env_vars = {}
            if os.path.exists(environ_path):
                raw_env = Path(environ_path).read_bytes().decode("utf-8", errors="replace")
                for var in raw_env.split("\x00"):
                    if "=" in var:
                        k, _, v = var.partition("=")
                        env_vars[k] = v

            name = self._extract_process_name(cmdline_clean, env_vars, pid, framework)
            if not self._is_agent_worthy(cmdline_clean, env_vars, framework, pid):
                return None

            port = self._extract_process_port(cmdline_clean, env_vars)
            caps = self._infer_process_capabilities(cmdline_clean, env_vars)

            return DiscoveredAgent(
                agent_id=env_vars.get("AGENT_ID") or env_vars.get("SAN_AGENT_ID"),
                name=name,
                source="process",
                framework=framework,
                pid=pid,
                port=port,
                status="running",
                capabilities=caps,
                extra={
                    "cmdline": cmdline_clean[:300],
                    "env_keys": list(env_vars.keys())[:20],
                },
            )
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def _match_framework(self, cmdline: str) -> str:
        lower = cmdline.lower()
        for fw, markers in self.FRAMEWORK_MARKERS.items():
            if any(m in lower for m in markers):
                return fw
        return "custom"

    def _is_agent_worthy(self, cmdline: str, env_vars: dict, framework: str, pid: int) -> bool:
        if framework != "custom":
            return True
        lower = cmdline.lower()
        strong_keywords = [
            "agent", "llm", "mcp", "orchestrat", "langchain", "crewai", "autogen",
            "llama_index", "openai.agent", "mcp.server", "fastmcp", "smolagents",
        ]
        if any(kw in lower for kw in strong_keywords):
            return True
        weak_keywords = ["ai-", "bot", "crew", "assistant", "tool-call"]
        weak_hits = sum(1 for k in weak_keywords if k in lower)
        env_prefixes = ["MCP_", "AGENT_", "SAN_", "LLM_", "OLLAMA_", "ANTHROPIC_API"]
        env_hits = sum(1 for k in env_vars for p in env_prefixes if k.startswith(p))
        if weak_hits >= 2 or env_hits >= 2:
            return True
        return False

    def _extract_process_name(self, cmdline: str, env_vars: dict, pid: int, framework: str) -> str:
        name = env_vars.get("AGENT_NAME") or env_vars.get("SAN_AGENT_NAME")
        if name:
            return name
        parts = cmdline.split()
        if parts and "python" in parts[0].lower():
            filtered = [p for p in parts if not p.startswith("-") and ".py" not in p.lower()]
            if filtered and filtered[0] not in ("python", "python3"):
                return filtered[0]
            script = next((p for p in parts if p.endswith(".py")), None)
            if script:
                return Path(script).stem
        return f"{framework}-agent-pid{pid}"

    def _extract_process_port(self, cmdline: str, env_vars: dict) -> Optional[int]:
        for env_key in ("PORT", "MCP_PORT", "API_PORT", "SAN_PORT", "AGENT_PORT", "SERVER_PORT"):
            val = env_vars.get(env_key)
            if val and val.isdigit():
                return int(val)
        import re
        port_match = re.search(r"(?:--port|=port)\s*(\d{2,5})", cmdline)
        if port_match:
            return int(port_match.group(1))
        return None

    def _infer_process_capabilities(self, cmdline: str, env_vars: dict) -> list[str]:
        caps = set()
        cap_str = env_vars.get("AGENT_CAPABILITIES") or env_vars.get("SAN_CAPABILITIES")
        if cap_str:
            for c in cap_str.split(","):
                caps.add(c.strip())
        lower = cmdline.lower()
        if "docker" in lower:
            caps.add("container_management")
        if "sql" in lower:
            caps.add("database_access")
        if "http" in lower or "request" in lower:
            caps.add("network_access")
        if "file" in lower or "read" in lower or "write" in lower:
            caps.add("file_access")
        return sorted(caps) if caps else ["execute"]


#
#  4. NETWORK BROADCAST SCANNER (mDNS / SSDP)
#

class NetworkBroadcastScanner(BaseScanner):
    name = "network"

    MDNS_MULTICAST_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    SSDP_MULTICAST_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    LISTEN_TIMEOUT = 4.0

    def scan(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []

        avahi_results = self._scan_via_avahi()
        results.extend(avahi_results)

        mdns_results = self._scan_mdns_direct()
        results.extend(mdns_results)

        ssdp_results = self._scan_ssdp_direct()
        results.extend(ssdp_results)

        seen = set()
        deduped: list[DiscoveredAgent] = []
        for agent in results:
            key = (agent.name, agent.port, agent.host)
            if key not in seen:
                seen.add(key)
                deduped.append(agent)
        return deduped

    def _scan_via_avahi(self) -> list[DiscoveredAgent]:
        import shutil
        if not shutil.which("avahi-browse"):
            return []

        import subprocess
        results: list[DiscoveredAgent] = []
        for service_type in ("_http._tcp", "_https._tcp", "_mcp._tcp", "_ws._tcp", "_san._tcp"):
            try:
                proc = subprocess.run(
                    ["avahi-browse", "-t", "-r", "-p", service_type],
                    capture_output=True, text=True, timeout=8,
                )
                if proc.returncode != 0:
                    continue
                for line in proc.stdout.strip().split("\n"):
                    agent = self._parse_avahi_line(line)
                    if agent:
                        results.append(agent)
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue
        return results

    def _parse_avahi_line(self, line: str) -> Optional[DiscoveredAgent]:
        if not line or line.startswith("#"):
            return None
        parts = line.split(";")
        if len(parts) < 8:
            return None
        try:
            hostname = parts[6]
            address = parts[7]
            port = int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else None
            service_name = parts[3] if len(parts) > 3 else hostname

            framework = self._detect_from_service_name(service_name, hostname)

            return DiscoveredAgent(
                agent_id=None,
                name=service_name or hostname,
                source="network",
                framework=framework,
                host=address,
                port=port,
                status="broadcasting",
                extra={
                    "protocol": "mDNS",
                    "service_type": parts[1] if len(parts) > 1 else "",
                    "hostname": hostname,
                },
            )
        except (IndexError, ValueError):
            return None

    def _scan_mdns_direct(self) -> list[DiscoveredAgent]:
        discovered: list[dict] = []
        received = threading.Event()

        def listener():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(self.LISTEN_TIMEOUT)
                sock.bind(("0.0.0.0", 5353))
                mreq = struct.pack("4sl", socket.inet_aton(self.MDNS_MULTICAST_ADDR), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                return

            start = time.time()
            while time.time() - start < self.LISTEN_TIMEOUT:
                try:
                    data, addr = sock.recvfrom(4096)
                    info = self._parse_mdns_packet(data, addr)
                    if info and info.get("name"):
                        discovered.append(info)
                        received.set()
                except socket.timeout:
                    break
                except OSError:
                    break
            sock.close()

        thread = threading.Thread(target=listener, daemon=True)
        thread.start()

        self._send_mdns_query()
        thread.join(timeout=self.LISTEN_TIMEOUT + 1)

        agents = [self._mdns_info_to_agent(i) for i in discovered if i.get("name")]
        agents = [a for a in agents if a is not None]
        return agents

    def _send_mdns_query(self):
        query_services = [
            "_mcp._tcp.local",
            "_http._tcp.local",
            "_https._tcp.local",
            "_san._tcp.local",
        ]
        for service in query_services:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.settimeout(1)
                query = self._build_mdns_query(service)
                sock.sendto(query, (self.MDNS_MULTICAST_ADDR, 5353))
            except OSError:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

    @staticmethod
    def _build_mdns_query(service: str) -> bytes:
        labels = service.split(".")
        qname = b"".join(len(l).to_bytes(1, "big") + l.encode() for l in labels) + b"\x00"
        header = struct.pack("!HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
        question = qname + struct.pack("!HH", 12, 1)
        return header + question

    @staticmethod
    def _parse_mdns_packet(data: bytes, addr: tuple) -> Optional[dict]:
        if len(data) < 12:
            return None
        return {
            "name": f"mdns-service-{addr[1]}",
            "host": addr[0],
            "port": addr[1],
            "protocol": "mDNS",
        }

    def _mdns_info_to_agent(self, info: dict) -> DiscoveredAgent:
        name = info.get("name", "")
        if name.startswith("mdns-service-"):
            return None
        return DiscoveredAgent(
            agent_id=None,
            name=name,
            source="network",
            framework=self._detect_from_service_name(name, info.get("host", "")),
            host=info.get("host", "localhost"),
            port=info.get("port"),
            status="broadcasting",
            extra=info,
        )

    def _scan_ssdp_direct(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []
        ssdp_msgs = [
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:service:Agent:1\r\n\r\n",
        ]

        for msg in ssdp_msgs:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.settimeout(2.0)
                sock.sendto(msg, (self.SSDP_MULTICAST_ADDR, self.SSDP_PORT))

                while True:
                    try:
                        data, addr = sock.recvfrom(4096)
                        agent = self._parse_ssdp_response(data, addr)
                        if agent:
                            results.append(agent)
                    except socket.timeout:
                        break
                sock.close()
            except OSError:
                continue

        return results

    def _parse_ssdp_response(self, data: bytes, addr: tuple) -> Optional[DiscoveredAgent]:
        try:
            text = data.decode("utf-8", errors="replace")
            agent_keywords = ["agent", "mcp", "llm", "ai", "bot", "crew", "langchain", "autogen", "san", "secureagent"]
            if not any(kw in text.lower() for kw in agent_keywords):
                return None
            lines = text.split("\r\n")
            location = ""
            server_name = ""
            for line in lines:
                if line.upper().startswith("LOCATION:"):
                    location = line.split(":", 1)[1].strip()
                elif line.upper().startswith("SERVER:"):
                    server_name = line.split(":", 1)[1].strip()

            framework = self._detect_from_service_name(server_name, addr[0])

            return DiscoveredAgent(
                agent_id=None,
                name=server_name or f"ssdp-device-{addr[0]}",
                source="network",
                framework=framework,
                host=addr[0],
                port=None,
                status="broadcasting",
                extra={
                    "protocol": "SSDP",
                    "location": location,
                    "server": server_name,
                },
            )
        except Exception:
            return None

    @staticmethod
    def _detect_from_service_name(service_name: str, hostname: str) -> str:
        combined = (service_name + " " + hostname).lower()
        if "agent" in combined or "san" in combined:
            return "secure-agent"
        if "langchain" in combined:
            return "langchain"
        if "autogen" in combined:
            return "autogen"
        if "crew" in combined:
            return "crewai"
        if "ollama" in combined:
            return "ollama"
        return "network-service"


#
#  5. FILESYSTEM SCANNER
#

class FilesystemScanner(BaseScanner):
    name = "filesystem"

    SEARCH_PATHS = [
        Path.home() / ".mcp",
        Path.home() / ".config" / "mcp",
        Path.home() / ".crewai",
        Path.home() / ".autogen",
        Path.home() / ".langchain",
        Path.home() / ".san",
        Path.home() / ".secureagentnet",
        Path.home() / ".openai-agents",
        Path.home() / ".smolagents",
        Path.home() / ".llama",
        Path.home() / ".ollama",
        Path("/etc/mcp"),
        Path("/etc/san"),
        Path("/etc/agent"),
        Path("/opt/agents"),
        Path.home() / "agents",
        Path.home() / "crewai_projects",
    ]

    CONFIG_PATTERNS = [
        "mcp_config.json", "mcp.json",
        "agent_config.yaml", "agent_config.yml", "agent.json",
        "crew.yaml", "crew.json", "crews.yaml",
        "autogen_config.json",
        "san_config.yaml", "san_config.json",
        "agent_manifest.json",
        "langchain_config.yaml",
        "tools.json", "tools.yaml",
        ".env.agent",
    ]

    def scan(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []
        seen_dirs: set[str] = set()

        for search_path in self.SEARCH_PATHS:
            expanded = search_path.expanduser().resolve()
            if not expanded.exists():
                continue
            if str(expanded) in seen_dirs:
                continue
            seen_dirs.add(str(expanded))

            agents = self._scan_directory(expanded)
            results.extend(agents)

        results.extend(self._scan_global_configs())
        results.extend(self._scan_docker_compose_files())

        return results

    def _scan_directory(self, directory: Path) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []
        try:
            for item in directory.iterdir():
                if item.name in self.CONFIG_PATTERNS:
                    agent = self._parse_config_file(item)
                    if agent:
                        results.append(agent)

                if item.is_dir():
                    agent_subdir = self._check_agent_subdir(item)
                    if agent_subdir:
                        results.append(agent_subdir)

            agents_json = directory / "agents.json"
            if agents_json.exists():
                results.extend(self._parse_agents_json(agents_json))

        except (PermissionError, OSError):
            pass
        return results

    def _check_agent_subdir(self, directory: Path) -> Optional[DiscoveredAgent]:
        agent_files = [
            directory / "config.yaml",
            directory / "config.json",
            directory / "manifest.json",
            directory / "agent.py",
            directory / "main.py",
            directory / "crew.py",
        ]
        for f in agent_files:
            if f.exists():
                caps = []
                for config_file in directory.glob("*.json"):
                    try:
                        data = json.loads(config_file.read_text())
                        if isinstance(data, dict):
                            caps.extend(data.get("capabilities", []))
                            caps.extend(data.get("tools", []))
                    except (json.JSONDecodeError, OSError):
                        pass
                return DiscoveredAgent(
                    agent_id=None,
                    name=directory.name,
                    source="filesystem",
                    framework=self._guess_framework(directory.name, str(directory)),
                    config_path=str(directory),
                    status="configured",
                    capabilities=list(set(caps)) if caps else [],
                    extra={"agent_dir": str(directory)},
                )
        return None

    def _parse_config_file(self, config_file: Path) -> Optional[DiscoveredAgent]:
        try:
            content = config_file.read_text(encoding="utf-8", errors="replace")
            data = None
            if config_file.suffix in (".json"):
                data = json.loads(content)
            elif config_file.suffix in (".yaml", ".yml"):
                try:
                    import yaml
                    data = yaml.safe_load(content)
                except Exception:
                    data = {"raw": content[:500]}
            else:
                data = {"raw": content[:500]}
        except Exception:
            return None

        if data is None:
            return None

        if isinstance(data, dict):
            name = (
                data.get("name")
                or data.get("agent_name")
                or data.get("app_name")
                or config_file.stem
            )
            caps = (
                data.get("capabilities", [])
                or data.get("tools", [])
                or list(data.get("agents", {}).get("capabilities", []))
            )
            return DiscoveredAgent(
                agent_id=data.get("agent_id") or data.get("id"),
                name=str(name),
                source="filesystem",
                framework=self._guess_framework(str(name), content[:500]),
                config_path=str(config_file),
                status="configured",
                capabilities=caps if isinstance(caps, list) else [],
                extra={"config_file": config_file.name, "keys": list(data.keys())[:15]},
            )
        return None

    def _parse_agents_json(self, agents_file: Path) -> list[DiscoveredAgent]:
        try:
            data = json.loads(agents_file.read_text())
            agents = data if isinstance(data, list) else data.get("agents", [])
            results: list[DiscoveredAgent] = []
            for ag in agents:
                if isinstance(ag, dict):
                    results.append(DiscoveredAgent(
                        agent_id=ag.get("id") or ag.get("agent_id"),
                        name=ag.get("name", "unknown"),
                        source="filesystem",
                        framework=ag.get("type", ag.get("framework", "unknown")),
                        config_path=str(agents_file),
                        status=ag.get("status", "configured"),
                        capabilities=ag.get("capabilities", []),
                        extra={"config_file": agents_file.name},
                    ))
            return results
        except (json.JSONDecodeError, OSError):
            return []

    def _scan_global_configs(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []

        compose_files = list(Path.home().glob("**/docker-compose*.yml"))
        compose_files += list(Path.home().glob("**/compose*.yaml"))
        for cf in compose_files[:5]:
            try:
                import yaml
                data = yaml.safe_load(cf.read_text())
                if isinstance(data, dict) and "services" in data:
                    for svc_name, svc_config in data["services"].items():
                        if self._looks_like_agent_service(svc_name, svc_config):
                            results.append(DiscoveredAgent(
                                agent_id=None,
                                name=svc_name,
                                source="filesystem",
                                framework=self._guess_framework(svc_name, str(svc_config)),
                                config_path=str(cf),
                                status="compose-defined",
                                capabilities=self._extract_compose_caps(svc_config),
                                extra={"compose_file": str(cf)},
                            ))
            except Exception:
                pass
        return results

    def _scan_docker_compose_files(self) -> list[DiscoveredAgent]:
        results: list[DiscoveredAgent] = []
        search_roots = [Path.cwd(), Path.home()]
        for root in search_roots:
            for pattern in ("**/docker-compose*.yml", "**/docker-compose*.yaml", "**/compose*.yaml"):
                for cf in root.glob(pattern):
                    if len(results) >= 10:
                        return results
                    try:
                        import yaml
                        data = yaml.safe_load(cf.read_text())
                        if isinstance(data, dict) and "services" in data:
                            for svc_name, svc_config in data["services"].items():
                                if self._looks_like_agent_service(svc_name, svc_config):
                                    results.append(DiscoveredAgent(
                                        agent_id=None,
                                        name=svc_name,
                                        source="filesystem",
                                        framework=self._guess_framework(svc_name, str(svc_config)),
                                        config_path=str(cf),
                                        status="compose-defined",
                                        extra={"compose_file": str(cf)},
                                    ))
                    except Exception:
                        pass
        return results

    @staticmethod
    def _looks_like_agent_service(name: str, config: dict) -> bool:
        combined = (name + " " + str(config)).lower()
        agent_keywords = ["agent", "mcp", "llm", "crew", "autogen", "langchain", "san"]
        env = config.get("environment", {})
        if isinstance(env, list):
            env_str = " ".join(env).lower()
        elif isinstance(env, dict):
            env_str = " ".join(env.values()).lower()
        else:
            env_str = ""
        combined += " " + env_str
        labels = config.get("labels", {})
        if isinstance(labels, dict):
            combined += " " + " ".join(str(v) for v in labels.values())
        return any(kw in combined for kw in agent_keywords) and name.lower() not in ("postgres", "vault", "redis", "nginx", "traefik")

    @staticmethod
    def _guess_framework(name: str, content: str) -> str:
        combined = (name + " " + content).lower()
        if "crewai" in combined or "crew-ai" in combined:
            return "crewai"
        if "langchain" in combined or "langgraph" in combined:
            return "langchain"
        if "autogen" in combined:
            return "autogen"
        if "secureagentnet" in combined or "san" in combined:
            return "secureagentnet"
        if "mcp" in combined:
            return "mcp-server"
        if "ollama" in combined:
            return "ollama"
        if "agent" in combined:
            return "custom-agent"
        return "unknown"

    @staticmethod
    def _extract_compose_caps(config: dict) -> list[str]:
        caps = set()
        if config.get("privileged"):
            caps.add("privileged")
        if config.get("network_mode") == "host":
            caps.add("host_network")
        volumes = config.get("volumes", [])
        for v in volumes:
            if isinstance(v, str) and "/var/run/docker.sock" in v:
                caps.add("docker_socket")
        env = config.get("environment", {})
        if isinstance(env, list):
            env = dict(e.split("=", 1) for e in env if "=" in e)
        cap_str = env.get("AGENT_CAPABILITIES", "")
        if cap_str:
            caps.update(c.strip() for c in cap_str.split(","))
        return sorted(caps) if caps else []



#  ORCHESTRATOR


class AgentDiscoveryOrchestrator:
    SCANNERS: list[type[BaseScanner]] = [
        DockerSocketScanner,
        McpPortScanner,
        ProcessScanner,
        NetworkBroadcastScanner,
        FilesystemScanner,
    ]

    @classmethod
    def discover_all(cls, scanners: Optional[list[str]] = None, deduplicate: bool = True) -> list[DiscoveredAgent]:
        logger.info("Starting agent discovery across all scanners...")
        all_results: list[DiscoveredAgent] = []

        scanner_map = {s.name: s for s in cls.SCANNERS}
        active = [scanner_map[n] for n in (scanners or scanner_map.keys()) if n in scanner_map]

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(s().scan): s.name for s in active}
            for future in as_completed(futures):
                scanner_name = futures[future]
                try:
                    results = future.result(timeout=30)
                    all_results.extend(results)
                    logger.info("%s scanner found %d candidates", scanner_name, len(results))
                except Exception as exc:
                    logger.warning("%s scanner failed: %s", scanner_name, exc)

        if deduplicate:
            all_results = cls._deduplicate(all_results)

        logger.info("Discovery complete: %d unique agents found", len(all_results))
        return all_results

    @staticmethod
    def _deduplicate(agents: list[DiscoveredAgent]) -> list[DiscoveredAgent]:
        seen_names: set[str] = set()
        seen_ports: dict[int, str] = {}
        seen_containers: set[str] = set()
        unique: list[DiscoveredAgent] = []

        for agent in agents:
            if agent.container_id and agent.container_id in seen_containers:
                continue
            if agent.port and agent.port in seen_ports and agent.name == seen_ports[agent.port]:
                continue
            if agent.name in seen_names and agent.source != "docker":
                continue

            seen_names.add(agent.name)
            if agent.port:
                seen_ports[agent.port] = agent.name
            if agent.container_id:
                seen_containers.add(agent.container_id)
            unique.append(agent)

        return unique

    @staticmethod
    def list_scanners() -> list[str]:
        return [s.name for s in AgentDiscoveryOrchestrator.SCANNERS]
