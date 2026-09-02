@echo off
REM ============================================
REM SecAutoMind - Stop running server
REM ============================================
chcp 65001 >nul
setlocal

set "EXE=secautomind-ai.exe"

tasklist /FI "IMAGENAME eq %EXE%" 2>NUL | find /I /N "%EXE%" >NUL
if not "%ERRORLEVEL%"=="0" (
    echo [INFO] %EXE% is not running.
    goto :done
)

echo [INFO] Stopping %EXE% ...
taskkill /F /IM "%EXE%" >NUL 2>&1
if "%ERRORLEVEL%"=="0" (
    echo [OK] Stopped.
) else (
    echo [WARN] Failed to stop. Try running as Administrator.
)

:done
endlocal
exit /b 0
