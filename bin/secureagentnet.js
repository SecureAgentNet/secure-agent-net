#!/usr/bin/env node
/**
 * SecureAgentNet CLI — npm wrapper
 *
 * This is a thin Node.js wrapper that delegates to the Python CLI.
 * The Python runtime is installed via postinstall hook.
 *
 * Usage: npx secureagentnet --help
 *        npm install -g secureagentnet
 *        secureagentnet agent list
 */

const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const PYTHON = process.env.SECUREAGENTNET_PYTHON || "python3";
const INSTALL_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".secureagentnet"
);

function findPython() {
  const candidates = ["python3", "python3.11", "python3.12", "python3.10", "python"];
  for (const cmd of candidates) {
    try {
      execSync(`${cmd} --version`, { stdio: "ignore" });
      return cmd;
    } catch {
      continue;
    }
  }
  return null;
}

function runCLI() {
  const python = findPython();
  if (!python) {
    console.error(
      "SecureAgentNet requires Python 3.10+.\n" +
      "Install: https://www.python.org/downloads/\n" +
      "Or use:  pip install secureagentnet"
    );
    process.exit(1);
  }

  const cliPath = path.join(INSTALL_DIR, "src", "interfaces", "cli", "terminal.py");
  const wrapperPath = path.join(INSTALL_DIR, "bin", "secureagentnet");

  let scriptPath;
  if (fs.existsSync(wrapperPath)) {
    scriptPath = wrapperPath;
  } else if (fs.existsSync(cliPath)) {
    scriptPath = cliPath;
  } else {
    // Try pip-installed version
    try {
      execSync(`${python} -m secureagentnet --version 2>/dev/null || ${python} -c "from src.interfaces.cli.terminal import cli; cli()" --help`, {
        cwd: __dirname,
        stdio: "inherit",
      });
      return;
    } catch {
      console.error(
        "SecureAgentNet not found.\n" +
        "Install: curl -fsSL https://secureagentnet.dev/install.sh | sh\n" +
        "   or:   pip install secureagentnet"
      );
      process.exit(1);
    }
  }

  const args = process.argv.slice(2);
  const child = spawn(python, [scriptPath, ...args], {
    stdio: "inherit",
    env: { ...process.env, INSTALL_DIR },
  });

  child.on("exit", (code) => process.exit(code));
  child.on("error", (err) => {
    console.error(`Failed to start SecureAgentNet: ${err.message}`);
    process.exit(1);
  });
}

runCLI();
