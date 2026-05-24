#!/usr/bin/env node
/**
 * SecureAgentNet — npm preuninstall script
 */

const path = require("path");
const fs = require("fs");

const INSTALL_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".secureagentnet"
);

try {
  if (fs.existsSync(INSTALL_DIR)) {
    fs.rmSync(INSTALL_DIR, { recursive: true, force: true });
    console.log("🗑️  SecureAgentNet data directory removed.");
  }
} catch {
  // Ignore cleanup errors
}
