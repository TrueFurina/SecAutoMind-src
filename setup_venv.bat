@echo off
REM ============================================
REM SecAutoMind - One-time venv setup
REM Creates a fresh venv in the current directory
REM ============================================
setlocal

echo.
echo ============================================
echo   SecAutoMind venv setup
echo ============================================
echo.

REM --- Check Python ---
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    echo         Install Python 3.10+ from https://www.python.org/downloads/
    echo         During install, check "Add Python to PATH"
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [INFO] Detected Python %PYVER%

REM --- Verify Python version ---
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (
    echo [ERROR] Python 3.10+ required, found %PYVER%.
    pause
    exit /b 1
)

REM --- Remove old venv if exists ---
if exist venv (
    echo [INFO] Removing existing venv...
    rmdir /s /q venv
)

REM --- Create new venv ---
echo [INFO] Creating fresh venv...
python -m venv --copies venv
if errorlevel 1 (
    echo [ERROR] Failed to create venv.
    pause
    exit /b 1
)

REM --- Upgrade pip ---
echo [INFO] Upgrading pip...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
if errorlevel 1 (
    echo [WARN] pip upgrade failed, continuing anyway...
)

REM --- Install dependencies ---
echo [INFO] Installing dependencies from requirements.txt...
pip install -r requirements.txt
if errorlevel 1 (
    echo [WARN] Some packages failed to install. Check errors above.
    echo        The main secautomind-ai.exe does NOT need Python,
    echo        so the service will still run.
)

echo.
echo [OK] venv setup complete.
echo     To use venv manually:  venv\Scripts\activate
echo     Or just run:           start.bat
echo.
endlocal
pause
exit /b 0
