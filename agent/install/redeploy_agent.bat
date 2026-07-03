@echo off
setlocal EnableExtensions EnableDelayedExpansion
REM ============================================================================
REM  XORCISM XOR agent - hot redeploy of the packaged executable
REM ----------------------------------------------------------------------------
REM  Swaps a freshly built xor_agent.exe in while the agent runs as a service.
REM  The running binary is locked by the service, so this script:
REM    1. backs up the current exe to xor_agent.exe.prev  (rollback slot)
REM    2. stops the XORCISMXORAgent service + any residual processes
REM    3. copies the new build over dist\xor_agent.exe
REM    4. restarts the service and shows its state
REM  Stopping the service needs Administrator rights, so it self-elevates (UAC).
REM
REM  Usage (right-click > Run as administrator, or it self-elevates):
REM    redeploy_agent.bat                    Deploy dist\xor_agent.new.exe  (default)
REM    redeploy_agent.bat <path-to-new-exe>  Deploy a specific new build
REM    redeploy_agent.bat rollback           Restore dist\xor_agent.exe.prev
REM    redeploy_agent.bat status             Show service + process state
REM ============================================================================

set "SVCNAME=XORCISMXORAgent"

REM --- self-elevate to Administrator if needed --------------------------------
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Requesting administrator privileges...
  if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  ) else (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
  )
  exit /b
)

REM --- locate the live agent executable ---------------------------------------
set "EXE="
if exist "%~dp0xor_agent.exe"                     set "EXE=%~dp0xor_agent.exe"
if not defined EXE if exist "%~dp0..\dist\xor_agent.exe" set "EXE=%~dp0..\dist\xor_agent.exe"
if not defined EXE if exist "%~dp0dist\xor_agent.exe"    set "EXE=%~dp0dist\xor_agent.exe"
if not defined EXE (
  echo [ERROR] xor_agent.exe not found next to this script, in .\dist or ..\dist .
  goto :end
)
for %%I in ("%EXE%") do set "EXEDIR=%%~dpI"
set "PREV=%EXE%.prev"

if /I "%~1"=="status"   goto :status
if /I "%~1"=="rollback" goto :rollback

REM --- resolve the new build to deploy ----------------------------------------
set "NEWEXE=%~1"
if not defined NEWEXE set "NEWEXE=%EXEDIR%xor_agent.new.exe"
if not exist "%NEWEXE%" (
  echo [ERROR] New build not found: %NEWEXE%
  echo         Build it first:  pyinstaller --onefile xor_agent.py
  echo         then place it as dist\xor_agent.new.exe ^(or pass its path^).
  goto :end
)

echo.
echo  XORCISM XOR agent - hot redeploy
echo  --------------------------------
echo   Service    : %SVCNAME%
echo   Live exe   : %EXE%
echo   New build  : %NEWEXE%
echo   Rollback   : %PREV%
echo.

echo [1/5] Backing up the current binary to xor_agent.exe.prev ...
copy /Y "%EXE%" "%PREV%" >nul
if not "%errorlevel%"=="0" echo       [WARN] backup failed ^(continuing^).

echo [2/5] Stopping the service ...
net stop "%SVCNAME%" >nul 2>&1
timeout /t 2 /nobreak >nul
taskkill /f /im xor_agent.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [3/5] Swapping the binary ...
copy /Y "%NEWEXE%" "%EXE%" >nul
if not "%errorlevel%"=="0" (
  echo       [ERROR] Copy failed - the file is still locked.
  echo       Restarting the service with the existing binary ...
  net start "%SVCNAME%" >nul 2>&1
  goto :end
)

echo [4/5] Starting the service ...
net start "%SVCNAME%" >nul 2>&1
if not "%errorlevel%"=="0" sc start "%SVCNAME%" >nul 2>&1
timeout /t 3 /nobreak >nul

echo [5/5] Verifying ...
goto :status

:rollback
if not exist "%PREV%" (
  echo [ERROR] No rollback backup found: %PREV%
  goto :end
)
echo Rolling back to the previous binary ...
net stop "%SVCNAME%" >nul 2>&1
timeout /t 2 /nobreak >nul
taskkill /f /im xor_agent.exe >nul 2>&1
timeout /t 2 /nobreak >nul
copy /Y "%PREV%" "%EXE%" >nul
if not "%errorlevel%"=="0" (
  echo [ERROR] Rollback copy failed - the file is still locked.
  net start "%SVCNAME%" >nul 2>&1
  goto :end
)
net start "%SVCNAME%" >nul 2>&1
if not "%errorlevel%"=="0" sc start "%SVCNAME%" >nul 2>&1
timeout /t 3 /nobreak >nul
echo [OK] Rolled back to %PREV%.
goto :status

:status
echo.
echo === Service "%SVCNAME%" ===
sc query "%SVCNAME%" 2>nul | findstr /I "SERVICE_NAME STATE" || echo   (service not installed)
echo.
echo === Live binary ===
for %%I in ("%EXE%") do echo   %%~fI  (%%~zI bytes, %%~tI)
echo.
echo === xor_agent.exe processes ===
tasklist /fi "imagename eq xor_agent.exe" /fo table 2>nul | findstr /I "xor_agent" || echo   (none running)
goto :end

:end
echo.
if "%~1"=="" pause
endlocal
