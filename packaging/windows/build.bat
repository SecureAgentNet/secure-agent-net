@echo off
REM Build a standalone Windows executable for SecureAgentNet Desktop.
cd /d "%~dp0\..\.."

echo Installing PyInstaller...
venv\Scripts\pip install pyinstaller

set ICON_ARG=
if exist "packaging\windows\icon.ico" set ICON_ARG=--icon packaging\windows\icon.ico

echo Building Windows executable...
venv\Scripts\pyinstaller ^
    --name SecureAgentNetDesktop ^
    --windowed ^
    --onefile ^
    %ICON_ARG% ^
    --add-data "config;config" ^
    --add-data "secureagentnet;secureagentnet" ^
    --hidden-import secureagentnet.daemon.daemon ^
    --hidden-import secureagentnet.desktop.app ^
    --hidden-import sqlalchemy.ext.baked ^
    --hidden-import pydantic ^
    --hidden-import fastapi ^
    --hidden-import uvicorn ^
    --hidden-import websockets ^
    secureagentnet\desktop\app.py

echo Build complete: dist\SecureAgentNetDesktop.exe
pause
