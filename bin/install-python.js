#!/usr/bin/env node
/**
 * SecureAgentNet — npm postinstall script
 * Ensures Python CLI dependencies are available when installed via npm
 */

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const INSTALL_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".secureagentnet"
);

console.log("\n🔧 SecureAgentNet: Installing Python dependencies...\n");

try {
  execSync(`${process.env.SECUREAGENTNET_PYTHON || "python3"} -m pip install --upgrade pip -q 2>/dev/null`, {
    stdio: "ignore",
  });
} catch {
  // pip upgrade is optional
}

try {
  // Copy project files to install directory
  const srcDir = path.join(__dirname, "..");
  if (!fs.existsSync(INSTALL_DIR)) {
    fs.mkdirSync(INSTALL_DIR, { recursive: true });
  }

  // Install Python packages
  execSync(
    `${process.env.SECUREAGENTNET_PYTHON || "python3"} -m pip install rich click fastapi uvicorn docker hvac cryptography pyjwt requests flask flask-cors flask-limiter pydantic pydantic-settings sqlalchemy psycopg2-binary python-dotenv pyyaml structlog prometheus-client -q 2>&1`,
    { stdio: "inherit" }
  );

  console.log("✅ Python dependencies installed successfully.");
  console.log("\nUsage:");
  console.log("  secureagentnet --help");
  console.log("  secureagentnet doctor");
  console.log("  secureagentnet agent list\n");
} catch (err) {
  console.error(
    "⚠️  Failed to install Python dependencies.\n" +
    "   Try installing manually:\n" +
    "   pip install secureagentnet\n" +
    "   or: curl -fsSL https://secureagentnet.dev/install.sh | sh\n"
  );
  process.exit(0); // Don't fail npm install
}
