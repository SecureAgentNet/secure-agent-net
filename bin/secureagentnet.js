#!/usr/bin/env node
/** Thin npm launcher for the SecureAgentNet Python CLI. */

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function pythonCandidates() {
  const candidates = [];
  if (process.env.SECUREAGENTNET_PYTHON) {
    candidates.push(process.env.SECUREAGENTNET_PYTHON);
  }

  const projectRoot = path.resolve(__dirname, "..");
  const home = process.env.HOME || process.env.USERPROFILE || "/tmp";
  if (process.platform === "win32") {
    candidates.push(
      path.join(projectRoot, "venv", "Scripts", "python.exe"),
      path.join(home, ".secureagentnet", "venv", "Scripts", "python.exe")
    );
  } else {
    candidates.push(
      path.join(projectRoot, "venv", "bin", "python"),
      path.join(home, ".secureagentnet", "venv", "bin", "python")
    );
  }
  candidates.push("python3", "python");
  return [...new Set(candidates)];
}

function supportsSecureAgentNet(python) {
  if ((python.includes(path.sep) || path.isAbsolute(python)) && !fs.existsSync(python)) {
    return false;
  }
  const check = spawnSync(
    python,
    ["-c", "import secureagentnet.interfaces.cli.terminal"],
    { stdio: "ignore" }
  );
  return !check.error && check.status === 0;
}

const python = pythonCandidates().find(supportsSecureAgentNet);
if (!python) {
  console.error(
    "SecureAgentNet's Python package is not installed.\n" +
    "From the repository run: python3 -m venv venv && venv/bin/pip install -e .\n" +
    "Then activate it with: source venv/bin/activate"
  );
  process.exit(1);
}

const result = spawnSync(
  python,
  ["-m", "secureagentnet.interfaces.cli.terminal", ...process.argv.slice(2)],
  { stdio: "inherit", env: process.env }
);

if (result.error) {
  console.error(`Failed to start SecureAgentNet: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
