@echo off
REM ==============================================================================
REM CodeGuardian: Windows Launcher for Fine-Tuning in WSL2
REM ==============================================================================

echo [CodeGuardian] Launching fine-tuning inside WSL2 Ubuntu environment...
wsl -d Ubuntu -e bash -ic "cd '$(wslpath '%CD%')' && bash train.sh"
pause
