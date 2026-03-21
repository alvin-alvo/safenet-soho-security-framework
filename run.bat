@echo off
setlocal enabledelayedexpansion
TITLE SafeNet Test Suite

echo ========================================================
echo   Running SafeNet Unified Test Suite
echo ========================================================
echo.

if not exist ".venv" (
    echo [ERROR] Virtual environment not found. Please run setup_env.bat first.
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat

echo [+] Executing pytest with coverage...
pytest tests/ -v --cov=api --cov=core --cov-report=term-missing

if !ERRORLEVEL! NEQ 0 (
    echo.
    echo [!] Some tests failed. Please review the output above.
) else (
    echo.
    echo [+] All tests completed successfully!
)

echo.
pause
