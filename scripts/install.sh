#!/usr/bin/env bash
set -euo pipefail

VERSION="${SAN_VERSION:-2.0.0}"
REPO="https://github.com/secure-agent-net/secure-agent-net"
INSTALL_DIR="${SAN_INSTALL_DIR:-$HOME/.secureagentnet}"
BIN_DIR="${SAN_BIN_DIR:-/usr/local/bin}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[SAN]${NC} $*"; }
ok()    { echo -e "${GREEN}[SAN]${NC} $*"; }
warn()  { echo -e "${YELLOW}[SAN]${NC} $*"; }
err()   { echo -e "${RED}[SAN]${NC} $*"; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *)       echo "unknown" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

check_python() {
    if command -v python3 &>/dev/null; then
        local pyver
        pyver=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
            ok "Python $pyver detected"
            return 0
        fi
    fi
    err "Python 3.10+ is required but not found."
    err "Install it: https://www.python.org/downloads/"
    exit 1
}

install_via_pip() {
    info "Installing SecureAgentNet v${VERSION} via pip..."
    python3 -m pip install --user "secureagentnet>=${VERSION}" 2>/dev/null || {
        warn "PyPI install failed, installing from git..."
        python3 -m pip install --user "git+${REPO}.git@v${VERSION}" 2>/dev/null || {
            err "Installation failed. Trying from source..."
            local tmpdir
            tmpdir=$(mktemp -d)
            git clone --depth 1 --branch "v${VERSION}" "${REPO}.git" "$tmpdir" 2>/dev/null || {
                git clone --depth 1 "${REPO}.git" "$tmpdir"
            }
            cd "$tmpdir"
            python3 -m pip install --user .
            cd - >/dev/null
            rm -rf "$tmpdir"
        }
    }
}

install_via_brew() {
    info "Detected Homebrew — installing via tap..."
    if ! command -v brew &>/dev/null; then
        err "Homebrew not found. Install it first: https://brew.sh"
        exit 1
    fi
    brew tap secure-agent-net/tap 2>/dev/null || true
    brew install secureagentnet
}

install_post_setup() {
    info "Running post-install setup..."
    mkdir -p "$INSTALL_DIR"/{data,profiles,env}
    python3 -m secureagentnet init --mode "${DEPLOY_MODE:-docker}" 2>/dev/null || {
        warn "Post-install init skipped (run 'secureagentnet init' manually)"
    }
}

print_next_steps() {
    echo ""
    echo "================================================"
    echo -e "  ${GREEN}SecureAgentNet v${VERSION} installed!${NC}"
    echo "================================================"
    echo ""
    echo "  Quick start:"
    echo ""
    echo -e "    ${YELLOW}# Check your system${NC}"
    echo "    secureagentnet doctor"
    echo ""
    echo -e "    ${YELLOW}# If Docker/Ollama/Redis are missing, use minimal mode${NC}"
    echo "    secureagentnet doctor --deploy-mode minimal"
    echo ""
    echo -e "    ${YELLOW}# Initialize with test data${NC}"
    echo "    secureagentnet init --seed"
    echo ""
    echo -e "    ${YELLOW}# Evaluate a test action (no Docker needed)${NC}"
    echo "    secureagentnet evaluate 'ls -la'"
    echo ""
    echo -e "    ${YELLOW}# Start the server${NC}"
    echo "    secureagentnet server start"
    echo ""
    echo "  For full features (Docker sandboxing, LLM eval, Redis rate limiting):"
    echo ""
    echo "    macOS:  brew install docker ollama redis"
    echo "    Linux:  sudo apt install docker.io ollama redis-server"
    echo "    Arch:   sudo pacman -S docker ollama redis"
    echo ""
}

main() {
    local os
    os=$(detect_os)
    info "Detected OS: $os ($(detect_arch))"

    check_python

    if [ "$os" = "macos" ] && command -v brew &>/dev/null; then
        install_via_brew
    else
        install_via_pip
    fi

    install_post_setup
    print_next_steps

    ok "Installation complete!"
    ok "Run 'secureagentnet doctor' to verify."
}

main "$@"
