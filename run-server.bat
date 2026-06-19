@echo off
REM ============================================================================
REM  XORCISM server launcher / relauncher
REM  - uses the portable Node 20 (better-sqlite3 ABI) bundled in tools\nodejs
REM  - stops any instance already listening on the port, then starts fresh
REM  Double-click to run, or call from a terminal. Ctrl+C to stop.
REM ============================================================================
title XORCISM server
setlocal
cd /d "%~dp0"

REM --- configuration (override by setting these before calling the script) ---
if not defined PORT set "PORT=9292"
if not defined DB_DIR set "DB_DIR=C:\Users\jerom\XORCISM_databases"
set "NODE=%~dp0tools\nodejs\node.exe"
set "SERVER=%~dp0xorcism_ts\dist\server\index.js"

if not exist "%NODE%" (
  echo [ERROR] Portable Node not found at "%NODE%"
  pause
  exit /b 1
)
if not exist "%SERVER%" (
  echo [ERROR] Server build not found at "%SERVER%"
  echo         Build it first:  cd xorcism_ts  ^&^&  npm run build
  pause
  exit /b 1
)

echo Stopping any XORCISM server already listening on port %PORT% ...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%PORT% " ^| findstr LISTENING') do taskkill /F /PID %%P >nul 2>&1

echo.
echo   XORCISM  -^>  http://localhost:%PORT%/login
echo   DB_DIR   =   %DB_DIR%
echo   Node     =   %NODE%
echo   (Press Ctrl+C to stop.)
echo.

"%NODE%" "%SERVER%"
endlocal
