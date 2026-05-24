#!/usr/bin/env bash
# Helper script to set up Docker Desktop for SecureAgentNet on macOS/Windows
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${CYAN}[SAN-Docker]${NC} $*"; }
ok()   { echo -e "${GREEN}[SAN-Docker]${NC} $*"; }
warn() { echo -e "${YELLOW}[SAN-Docker]${NC} $*"; }

echo "==========================================="
echo "  Docker Desktop Setup for SecureAgentNet   "
echo "==========================================="
echo ""

os=$(uname -s)

case "$os" in
    Darwin)
        info "Detected macOS"
        if ! command -v docker &>/dev/null; then
            warn "Docker not found. Install Docker Desktop:"
            echo "  brew install --cask docker"
            echo "  or download from https://www.docker.com/products/docker-desktop/"
            exit 1
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        info "Detected Windows (Git Bash / WSL)"
        if ! command -v docker &>/dev/null; then
            warn "Docker not found. Install Docker Desktop for Windows:"
            echo "  https://www.docker.com/products/docker-desktop/"
            exit 1
        fi
        ;;
    Linux)
        info "Detected Linux — Docker Engine is recommended over Docker Desktop"
        if ! command -v docker &>/dev/null; then
            warn "Docker not found. Install Docker Engine:"
            echo "  curl -fsSL https://get.docker.com | sh"
            exit 1
        fi
        ;;
esac

info "Checking Docker connection..."
if docker info &>/dev/null; then
    ok "Docker is running and responsive!"
else
    warn "Docker daemon is not responding. Make sure Docker Desktop is running."
    warn "  macOS: Launch Docker Desktop from Applications"
    warn "  Windows: Launch Docker Desktop from Start Menu"
    warn "  Linux: sudo systemctl start docker"
    exit 1
fi

ok "Docker is ready for SecureAgentNet container sandboxing."
ok "Run 'secureagentnet doctor' to verify."
