@echo off
cd /d  "%~dp0"
title STW console

rem Use pythonw.exe (no console window) so no black python.exe box appears.
rem If pythonw.exe is unavailable, fall back to python.exe.
if exist ".venv\Scripts\pythonw.exe" (
    ".venv\Scripts\pythonw.exe" -m stw_ui.stw_ui >> stw_stdout.txt 2>&1
) else (
    ".venv\Scripts\python.exe" -m stw_ui.stw_ui >> stw_stdout.txt 2>&1
)
set "rc=%errorlevel%"

echo [%DATE% %TIME%] batch-level exit code = %rc% >> stw_exit.txt
echo.
echo ==============================================
echo  Console stopped. exit code = %rc%
echo  Exit codes      : stw_exit.txt
echo  Python output   : stw_stdout.txt
echo  Hard crash stack: stw_crash.txt
echo  Last alive steps: stw_heartbeat.txt
echo  Press any key to close this window.
echo ==============================================
pause >nul
exit /b %rc%
