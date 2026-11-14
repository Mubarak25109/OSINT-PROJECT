@echo off
title LinkGuard OSINT
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 linkguard.py
) else (
    python linkguard.py
)
if errorlevel 1 (
    echo.
    echo LinkGuard could not start. Install Python 3 from https://www.python.org/downloads/
    echo During installation, enable "Add python.exe to PATH".
    pause
)
