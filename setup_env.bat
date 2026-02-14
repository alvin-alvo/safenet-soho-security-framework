@echo off
TITLE SafeNet Environment Setup
CLS

ECHO ========================================================
ECHO    SafeNet SOHO Security Framework - Setup Wizard
ECHO ========================================================
ECHO.

:: 1. Check Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO [ERROR] Python is not installed or not in PATH.
    ECHO Please install Python 3.10+ from python.org and try again.
    PAUSE
    EXIT /B 1
)

:: 2. Create Venv
IF NOT EXIST "venv" (
    ECHO [+] Creating Python Virtual Environment (venv)...
    python -m venv venv
) ELSE (
    ECHO [.] Virtual Environment already exists.
)

:: 3. Install Dependencies
ECHO [+] Installing Dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt
IF %ERRORLEVEL% NEQ 0 (
    ECHO [ERROR] Failed to install requirements.
    PAUSE
    EXIT /B 1
)

ECHO.
ECHO ========================================================
ECHO    SETUP COMPLETE!
ECHO ========================================================
ECHO.
ECHO You can now run the server using 'run_server.bat'
ECHO.
PAUSE
