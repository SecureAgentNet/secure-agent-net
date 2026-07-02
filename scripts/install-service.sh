#!/usr/bin/env bash
# Install SecureAgentNet as a systemd user service on Linux.
set -euo pipefail

SERVICE_NAME="secureagentnet"
SERVICE_SRC="deployment/systemd/secureagentnet.service"
SERVICE_DIR="${HOME}/.config/systemd/user"
SERVICE_DEST="${SERVICE_DIR}/${SERVICE_NAME}.service"

echo "Installing SecureAgentNet systemd user service..."

# Ensure source exists.
if [[ ! -f "${SERVICE_SRC}" ]]; then
    echo "ERROR: ${SERVICE_SRC} not found. Run this script from the project root."
    exit 1
fi

mkdir -p "${SERVICE_DIR}"
cp "${SERVICE_SRC}" "${SERVICE_DEST}"

# Update ExecStart to use the current virtual environment if present.
VENV_DAEMON="${PWD}/venv/bin/secureagentnet-daemon"
if [[ -x "${VENV_DAEMON}" ]]; then
    sed -i "s|%h/.local/share/secureagentnet/venv/bin/secureagentnet-daemon|${VENV_DAEMON}|g" "${SERVICE_DEST}"
fi

# Reload systemd user daemon and enable service.
systemctl --user daemon-reload
systemctl --user enable "${SERVICE_NAME}.service"
systemctl --user start "${SERVICE_NAME}.service"

echo "Service installed and started."
echo "Check status with: systemctl --user status ${SERVICE_NAME}"
