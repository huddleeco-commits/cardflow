@echo off
title SlabTrack Scanner - Restart
echo.
echo  === SlabTrack Desktop Scanner ===
echo  Closing all instances...
echo.

:: Kill all Electron/scanner processes
taskkill /f /im "slabtrack-desktop-scanner.exe" >nul 2>&1
taskkill /f /im "SlabTrack Desktop Scanner.exe" >nul 2>&1

:: Also kill any leftover electron.exe processes from dev mode
taskkill /f /im "electron.exe" >nul 2>&1

:: Small delay to let processes fully exit
timeout /t 2 /nobreak >nul

echo  All processes closed.
echo  Starting scanner...
echo.

:: Try installed location first (Squirrel install path)
set "INSTALLED=%LocalAppData%\slabtrack-desktop-scanner\SlabTrack Desktop Scanner.exe"
if exist "%INSTALLED%" (
    start "" "%INSTALLED%"
    echo  Launched from installed location.
    goto :done
)

:: Try current directory (portable/dev)
set "PORTABLE=%~dp0out\SlabTrack Desktop Scanner-win32-x64\SlabTrack Desktop Scanner.exe"
if exist "%PORTABLE%" (
    start "" "%PORTABLE%"
    echo  Launched from portable build.
    goto :done
)

:: Fallback: dev mode
echo  No built app found. Starting in dev mode...
cd /d "%~dp0"
start "" npm start

:done
echo.
echo  Done! You can close this window.
timeout /t 3 /nobreak >nul
