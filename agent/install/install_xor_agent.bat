@echo off
setlocal EnableExtensions
REM ============================================================================
REM  XORCISM XOR agent - Windows "service" installer
REM ----------------------------------------------------------------------------
REM  Enrolls the agent with the XORCISM server and registers it to run
REM  continuously as a SYSTEM scheduled task that:
REM    - starts automatically at boot (no logon needed),
REM    - runs with no time limit (so it never gets killed after 72h),
REM    - auto-restarts every minute if it stops,
REM  i.e. it behaves like a Windows service and "keeps running".
REM
REM  Usage (right-click > Run as administrator, or it self-elevates):
REM    install_xor_agent.bat <server-url> [enroll-key]   Enroll + install + start
REM    install_xor_agent.bat                             (Re)install with the
REM                                                       existing enrollment
REM    install_xor_agent.bat status                      Show task + process state
REM    install_xor_agent.bat uninstall                   Stop + remove the service
REM
REM  Examples:
REM    install_xor_agent.bat https://xorcism.lab:9292
REM    install_xor_agent.bat https://xorcism.lab:9292 my-enrollment-key
REM
REM  Requires: Windows 8 / Server 2012+ (PowerShell ScheduledTasks module).
REM ============================================================================

set "TASKNAME=XORCISM XOR Agent"
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

REM --- locate the agent executable (next to this script, or ..\dist, or .\dist)
set "EXE="
if exist "%~dp0xor_agent.exe"          set "EXE=%~dp0xor_agent.exe"
if not defined EXE if exist "%~dp0..\dist\xor_agent.exe" set "EXE=%~dp0..\dist\xor_agent.exe"
if not defined EXE if exist "%~dp0dist\xor_agent.exe"    set "EXE=%~dp0dist\xor_agent.exe"
if not defined EXE (
  echo [ERROR] xor_agent.exe not found next to this script, in .\dist or ..\dist .
  echo         Put this .bat alongside xor_agent.exe ^(or in agent\install^) and retry.
  goto :end
)
for %%I in ("%EXE%") do set "EXEDIR=%%~dpI"
set "CONF=%EXEDIR%xor_agent.conf"

if /I "%~1"=="status"    goto :status
if /I "%~1"=="uninstall" goto :uninstall
if /I "%~1"=="remove"    goto :uninstall

echo.
echo  XORCISM XOR agent service installer
echo  -----------------------------------
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

REM --- verify enrollment (the conf must now carry a token) ---------------------
if not exist "%CONF%" (
  echo [ERROR] Enrollment failed - no config was written. Check the server URL / key.
  goto :end
)
findstr /I "token" "%CONF%" >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [ERROR] Enrollment did not produce a token. Check the server URL / enrollment key.
  goto :end
)

REM --- register the service (SYSTEM scheduled task: boot-start, no time limit,
REM     auto-restart). Values are passed via env vars to avoid quoting issues. --
echo [2/3] Registering the "%TASKNAME%" service ^(boot-start, SYSTEM, auto-restart^) ...
set "XA_EXE=%EXE%"
set "XA_CONF=%CONF%"
set "XA_INTERVAL=%INTERVAL%"
set "XA_TASK=%TASKNAME%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $q=[char]34; $arg='--run --interval '+$env:XA_INTERVAL+' --conf '+$q+$env:XA_CONF+$q; $a=New-ScheduledTaskAction -Execute $env:XA_EXE -Argument $arg; $t=New-ScheduledTaskTrigger -AtStartup; $p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999 -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew; $null=Register-ScheduledTask -TaskName $env:XA_TASK -Action $a -Trigger $t -Principal $p -Settings $s -Force"
set "RC=%errorlevel%"
set "XA_EXE=" & set "XA_CONF=" & set "XA_INTERVAL=" & set "XA_TASK="
if not "%RC%"=="0" (
  echo [ERROR] Could not register the scheduled task ^(needs Windows 8 / Server 2012+^).
  goto :end
)

REM --- start it now -----------------------------------------------------------
echo [3/3] Starting the agent now ...
schtasks /run /tn "%TASKNAME%" >nul 2>&1

echo.
echo  [OK] Installed as the "%TASKNAME%" service and started.
echo       It checks in every %INTERVAL%s, runs as SYSTEM at boot, and restarts on failure.
echo.
echo       Manage:  %~nx0 status      ^|   %~nx0 uninstall
echo                or Task Scheduler ^> "%TASKNAME%"
goto :end

:status
echo.
echo === Scheduled task "%TASKNAME%" ===
schtasks /query /tn "%TASKNAME%" /fo LIST /v 2>nul | findstr /I "TaskName Status Result Next Run Logon" || echo   (task not installed)
echo.
echo === xor_agent.exe processes ===
tasklist /fi "imagename eq xor_agent.exe" /fo table 2>nul | findstr /I "xor_agent" || echo   (none running)
goto :end

:uninstall
echo Stopping and removing the "%TASKNAME%" service ...
schtasks /end    /tn "%TASKNAME%"    >nul 2>&1
schtasks /delete /tn "%TASKNAME%" /f >nul 2>&1
taskkill /f /im xor_agent.exe        >nul 2>&1
echo [OK] Service removed. The enrollment file was left in place:
echo      %CONF%
goto :end

:end
echo.
if "%~1"=="" pause
endlocal
