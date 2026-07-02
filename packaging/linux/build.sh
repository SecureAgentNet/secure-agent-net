#!/usr/bin/env bash
# Build a standalone Linux executable for SecureAgentNet Desktop.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "${PROJECT_ROOT}"

echo "Installing PyInstaller..."
venv/bin/pip install pyinstaller

ICON_ARG=""
if [[ -f "packaging/linux/icon.png" ]]; then
    ICON_ARG="--icon packaging/linux/icon.png"
fi

echo "Building Linux executable..."
venv/bin/pyinstaller \
    --name secureagentnet-desktop \
    --windowed \
    --onefile \
    ${ICON_ARG} \
    --add-data "config:config" \
    --add-data "secureagentnet:secureagentnet" \
    --hidden-import secureagentnet.daemon.daemon \
    --hidden-import secureagentnet.desktop.app \
    --hidden-import sqlalchemy.ext.baked \
    --hidden-import pydantic \
    --hidden-import fastapi \
    --hidden-import uvicorn \
    --hidden-import websockets \
    secureagentnet/desktop/app.py

echo "Build complete: dist/secureagentnet-desktop"
