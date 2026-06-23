@echo off
setlocal EnableExtensions
REM ============================================================================
REM  XORCISM XOR agent - real Windows service installer (via NSSM)
REM ----------------------------------------------------------------------------
REM  Registers the agent as a true SCM service (visible in services.msc), using
REM  NSSM (the Non-Sucking Service Manager) to host the console daemon. The
REM  service runs as LocalSystem, starts automatically at boot, and NSSM
REM  restarts it if it exits - so it "keeps running".
REM
REM  This is the services.msc alternative to install_xor_agent.bat (which uses a
REM  scheduled task instead). Use ONE of the two, not both.
REM
REM  Prerequisite: nssm.exe (https://nssm.cc/download). Put it next to this .bat,
REM  in ..\tools\, in .\nssm\, or anywhere on PATH.
REM
REM  Usage (right-click > Run as administrator, or it self-elevates):
REM    install_xor_agent_service.bat <server-url> [enroll-key]   Enroll+install+start
REM    install_xor_agent_service.bat                             (Re)install w/ existing enrollment
REM    install_xor_agent_service.bat status                      Show service state
REM    install_xor_agent_service.bat uninstall                   Stop + remove the service
REM ============================================================================

set "SVCNAME=XORCISMXORAgent"
set "DISPLAY=XORCISM XOR Agent"
set "INTERVAL=300"

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

REM --- locate nssm.exe (next to script, ..\tools, .\nssm, or PATH) -------------
set "NSSM="
if exist "%~dp0nssm.exe"                  set "NSSM=%~dp0nssm.exe"
if not defined NSSM if exist "%~dp0..\tools\nssm.exe" set "NSSM=%~dp0..\tools\nssm.exe"
if not defined NSSM if exist "%~dp0nssm\nssm.exe"     set "NSSM=%~dp0nssm\nssm.exe"
if not defined NSSM for %%X in (nssm.exe) do if not defined NSSM if not "%%~$PATH:X"=="" set "NSSM=%%~$PATH:X"
if not defined NSSM (
  echo [ERROR] nssm.exe not found.
  echo         Download it from https://nssm.cc/download and place nssm.exe next to
  echo         this script ^(or in ..\tools, .\nssm, or on PATH^), then re-run.
  echo         ^(For a no-dependency option, use install_xor_agent.bat instead -
  echo          it registers a boot-start scheduled task rather than a service.^)
  goto :end
)

REM --- locate the agent executable --------------------------------------------
set "EXE="
if exist "%~dp0xor_agent.exe"          set "EXE=%~dp0xor_agent.exe"
if not defined EXE if exist "%~dp0..\dist\xor_agent.exe" set "EXE=%~dp0..\dist\xor_agent.exe"
if not defined EXE if exist "%~dp0dist\xor_agent.exe"    set "EXE=%~dp0dist\xor_agent.exe"
if not defined EXE (
  echo [ERROR] xor_agent.exe not found next to this script, in .\dist or ..\dist .
  goto :end
)
for %%I in ("%EXE%") do set "EXEDIR=%%~dpI"
set "CONF=%EXEDIR%xor_agent.conf"

if /I "%~1"=="status"    goto :status
if /I "%~1"=="uninstall" goto :uninstall
if /I "%~1"=="remove"    goto :uninstall

echo.
echo  XORCISM XOR agent - real service installer ^(NSSM^)
echo  -------------------------------------------------
echo   NSSM       : %NSSM%
echo   Executable : %EXE%
echo   Config     : %CONF%
echo.

REM --- enrollment -------------------------------------------------------------
set "SERVER=%~1"
set "ENROLLKEY=%~2"
if not defined ENROLLKEY if defined XOR_ENROLL_KEY set "ENROLLKEY=%XOR_ENROLL_KEY%"
if defined SERVER (
  echo [1/3] Enrolling with %SERVER% ...
  if defined ENROLLKEY (
    "%EXE%" --enroll --server "%SERVER%" --enroll-key "%ENROLLKEY%" --conf "%CONF%"
  ) else (
    "%EXE%" --enroll --server "%SERVER%" --conf "%CONF%"
  )
) else (
  if not exist "%CONF%" (
    echo [ERROR] Not enrolled yet and no server URL was given.
    echo         Usage: %~nx0 ^<server-url^> [enroll-key]
    goto :end
  )
  echo [1/3] Using the existing enrollment ^(%CONF%^).
)
if not exist "%CONF%" (
  echo [ERROR] Enrollment failed - no config was written. Check the server URL / key.
  goto :end
)
findstr /I "token" "%CONF%" >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [ERROR] Enrollment did not produce a token. Check the server URL / enrollment key.
  goto :end
)

REM --- (re)create + configure the service -------------------------------------
REM  AppDirectory = the exe folder, so --conf can stay a bare filename (no path,
REM  hence no quoting headaches). NSSM restarts the process if it exits.
echo [2/3] Installing the "%DISPLAY%" service ...
sc query "%SVCNAME%" >nul 2>&1
if "%errorlevel%"=="0" (
  echo       Service already exists - reconfiguring; stopping it first ...
  "%NSSM%" stop "%SVCNAME%" >nul 2>&1
) else (
  "%NSSM%" install "%SVCNAME%" "%EXE%"
  if not "%errorlevel%"=="0" (
    echo [ERROR] nssm install failed.
    goto :end
  )
)
"%NSSM%" set "%SVCNAME%" Application "%EXE%"
"%NSSM%" set "%SVCNAME%" AppDirectory "%EXEDIR%"
"%NSSM%" set "%SVCNAME%" AppParameters "--run --interval %INTERVAL% --conf xor_agent.conf"
"%NSSM%" set "%SVCNAME%" DisplayName "%DISPLAY%"
"%NSSM%" set "%SVCNAME%" Description "XORCISM endpoint agent - periodic check-in, scans and DFIR."
"%NSSM%" set "%SVCNAME%" Start SERVICE_AUTO_START
"%NSSM%" set "%SVCNAME%" ObjectName LocalSystem
"%NSSM%" set "%SVCNAME%" AppStdout "%EXEDIR%xor_agent.service.log"
"%NSSM%" set "%SVCNAME%" AppStderr "%EXEDIR%xor_agent.service.log"
"%NSSM%" set "%SVCNAME%" AppRotateFiles 1
"%NSSM%" set "%SVCNAME%" AppRotateBytes 1048576
"%NSSM%" set "%SVCNAME%" AppExit Default Restart
"%NSSM%" set "%SVCNAME%" AppRestartDelay 60000

echo [3/3] Starting the service ...
"%NSSM%" start "%SVCNAME%" >nul 2>&1
if not "%errorlevel%"=="0" sc start "%SVCNAME%" >nul 2>&1

echo.
echo  [OK] Installed as the "%DISPLAY%" service ^(name: %SVCNAME%^) and started.
echo       Visible in services.msc; runs as LocalSystem at boot; restarts on exit.
echo       Logs: %EXEDIR%xor_agent.service.log
echo.
echo       Manage:  %~nx0 status   ^|   %~nx0 uninstall
echo                or  sc query %SVCNAME%   ^|   net stop %SVCNAME%   ^|   net start %SVCNAME%
goto :end

:status
echo.
echo === Service "%DISPLAY%" ^(%SVCNAME%^) ===
sc query "%SVCNAME%" 2>nul | findstr /I "SERVICE_NAME STATE" || echo   (service not installed)
if defined NSSM "%NSSM%" status "%SVCNAME%" 2>nul
echo.
echo === xor_agent.exe processes ===
tasklist /fi "imagename eq xor_agent.exe" /fo table 2>nul | findstr /I "xor_agent" || echo   (none running)
goto :end

:uninstall
echo Stopping and removing the "%DISPLAY%" service ...
"%NSSM%" stop "%SVCNAME%" >nul 2>&1
"%NSSM%" remove "%SVCNAME%" confirm >nul 2>&1
sc delete "%SVCNAME%" >nul 2>&1
taskkill /f /im xor_agent.exe >nul 2>&1
echo [OK] Service removed. The enrollment file was left in place:
echo      %CONF%
goto :end

:end
echo.
if "%~1"=="" pause
endlocal
