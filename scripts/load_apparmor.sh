#!/usr/bin/env bash
set -euo pipefail

PROFILE_NAME="securenet-agent"
PROFILE_DIR="$HOME/.secureagentnet/profiles"
PROFILE_PATH="$PROFILE_DIR/$PROFILE_NAME.aa"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}[AppArmor]${NC} $*"; }
ok()   { echo -e "${GREEN}[AppArmor]${NC} $*"; }
err()  { echo -e "${RED}[AppArmor]${NC} $*"; }

if [ "$(uname -s)" != "Linux" ]; then
    err "AppArmor is only available on Linux."
    exit 1
fi

if ! command -v apparmor_parser &>/dev/null; then
    err "apparmor_parser not found. Install apparmor:"
    err "  Ubuntu/Debian: sudo apt install apparmor-utils apparmor-profiles"
    err "  Arch:          sudo pacman -S apparmor"
    exit 1
fi

mkdir -p "$PROFILE_DIR"

if [ ! -f "$PROFILE_PATH" ]; then
    err "AppArmor profile not found at $PROFILE_PATH"
    err "Run 'secureagentnet doctor' first to generate the profile."
    exit 1
fi

info "Loading AppArmor profile: $PROFILE_NAME"
info "Profile path: $PROFILE_PATH"

if [ "$(id -u)" -eq 0 ]; then
    apparmor_parser -r "$PROFILE_PATH"
else
    info "Need sudo to load AppArmor profile..."
    sudo apparmor_parser -r "$PROFILE_PATH"
fi

# Verify loaded
if sudo apparmor_status 2>/dev/null | grep -q "$PROFILE_NAME"; then
    ok "Profile '$PROFILE_NAME' loaded successfully!"
else
    info "Profile may be loaded. Check: sudo apparmor_status | grep $PROFILE_NAME"
fi

ok "Run 'secureagentnet doctor' to verify AppArmor is detected."
