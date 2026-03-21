@echo off
setlocal enabledelayedexpansion
TITLE SafeNet Enterprise SOHO Framework - Setup

echo ========================================================
echo   SafeNet Zero-Trust Network Access Framework Setup
echo ========================================================
echo.

:: 1. Check Python installation
python --version >nul 2>&1
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

:: 2. Setup Virtual Environment
if not exist ".venv" (
    echo [+] Creating Python Virtual Environment .venv...
    python -m venv .venv
) else (
    echo [+] Virtual Environment already exists.
)

:: 3. Install/Upgrade Dependencies
echo [+] Upgrading pip and installing dependencies...
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if !ERRORLEVEL! NEQ 0 (
    echo [ERROR] Failed to install requirements.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   SETUP COMPLETE!
echo ========================================================
echo.
echo You can now start the gateway using 'run_server.bat'
echo or run tests using 'run.bat'
echo.
pause
