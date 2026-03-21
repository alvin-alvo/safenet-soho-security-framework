@echo off
setlocal enabledelayedexpansion
TITLE SafeNet API Gateway
cls

:: 1. Check Administrator Privileges
openfiles >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo.
    echo [ERROR] Administrator Privileges Required.
    echo This framework requires modifying IP forwarding and Windows Firewall.
    echo Please right-click this script and select "Run as Administrator".
    echo.
    pause
    exit /b 1
)

:: 2. Check Virtual Environment
if not exist ".venv" (
    echo [ERROR] Virtual environment not found.
    echo Please run 'setup_env.bat' first to install dependencies.
    pause
    exit /b 1
)

:: 3. Launch the Server
echo [+] Activating isolated environment...
call .venv\Scripts\activate.bat

echo [+] Initializing SafeNet Gateway...
python run_api.py

pause
