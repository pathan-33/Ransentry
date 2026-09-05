@echo off
title Ransomware Early Warning System Dashboard
cd /d "%~dp0"
echo Starting Ransomware Early Warning System...
python Ransomware.py
if %errorlevel% neq 0 (
    echo.
    echo An error occurred while running Ransomware.py.
    pause
)
