@echo off
REM ==============================================================================
REM CodeGuardian: Windows Launcher for Web UI
REM ==============================================================================

echo [CodeGuardian] Starting web server on http://localhost:8000 ...
python -m uvicorn app.server:app --host 127.0.0.1 --port 8000 --reload
if %ERRORLEVEL% NEQ 0 (
    echo [CodeGuardian] Local python failed or missing dependencies, routing through WSL2...
    wsl -d Ubuntu -e bash -ic "cd '$(wslpath '%CD%')' && bash run_app.sh"
)
pause
