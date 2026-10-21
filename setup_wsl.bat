@echo off
REM ==============================================================================
REM CodeGuardian: Windows Launcher for WSL2 Environment Setup
REM ==============================================================================

echo ======================================================================
echo  CodeGuardian: Initializing WSL2 Ubuntu Environment
echo ======================================================================
echo.
wsl -d Ubuntu -e bash -ic "cd '$(wslpath '%CD%')' && bash setup_wsl.sh"
echo.
echo Environment setup finished.
pause
