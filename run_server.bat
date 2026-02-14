@echo off
TITLE SafeNet API Server
CLS

:: 1. Check Admin Privileges
openfiles >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO.
    ECHO [ERROR] Administrator Privileges Required.
    ECHO.
    ECHO Please right-click this file and select "Run as Administrator".
    ECHO.
    PAUSE
    EXIT /B 1
)

:: 2. Check Venv
IF NOT EXIST "venv" (
    ECHO [ERROR] Virtual environment not found.
    ECHO Please run 'setup_env.bat' first.
    PAUSE
    EXIT /B 1
)

:: 3. Run Server
ECHO [+] Activating Environment...
call venv\Scripts\activate.bat

ECHO [+] Starting SafeNet API Server...
python run_api.py

PAUSE
