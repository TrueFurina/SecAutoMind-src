@echo off
REM ============================================
REM SecAutoMind - One-click launcher
REM ============================================
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "EXE=secautomind-ai.exe"
set "CFG=config.yaml"
set "PORT=8080"
set "URL=http://127.0.0.1:%PORT%/"

REM --- Already running? Just open browser ---
tasklist /FI "IMAGENAME eq %EXE%" 2>NUL | find /I /N "%EXE%" >NUL
if "%ERRORLEVEL%"=="0" (
    echo [INFO] %EXE% is already running.
    goto :open_browser
)

REM --- Pre-flight ---
if not exist "%EXE%" (
    echo [ERROR] %EXE% not found. Run build first.
    pause
    exit /b 1
)
if not exist "%CFG%" (
    if exist "config.example.yaml" (
        copy /Y "config.example.yaml" "%CFG%" >NUL
        echo [INFO] Created %CFG% from example template.
    ) else (
        echo [ERROR] %CFG% missing and no template to copy.
        pause
        exit /b 1
    )
)

echo [INFO] Starting SecAutoMind on port %PORT% ...
start "" /B "%EXE%" -config "%CFG%" --http

REM --- Wait for port to open (up to ~15s) ---
set /a tries=0
:wait_ready
set /a tries+=1
if %tries% GTR 30 (
    echo [WARN] Server did not respond within 15s. Check console output / config log file.
    goto :open_browser
)
timeout /t 1 /nobreak >NUL
netstat -ano | findstr ":%PORT% " | findstr "LISTENING" >NUL
if errorlevel 1 goto :wait_ready

echo [OK] Server is up.

:open_browser
echo.
echo  Login URL : %URL%
echo  Username  : admin
echo  Password  : (auto-generated at FIRST startup, printed in the server console window only once; if lost, run: %EXE% -config %CFG% --reset-admin-password)
echo.
start "" "%URL%"
endlocal
exit /b 0
