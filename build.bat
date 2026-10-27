@echo off
rem  SysPy top-level build.
rem
rem    build.bat        build the zip kit only
rem    build.bat exe    also compile the standalone .exe
rem
setlocal
cd /d "%~dp0"

where python >nul 2>&1 || (
    echo [x] python is not on PATH.
    pause
    exit /b 1
)

echo [1/2] Building distribution kit...
python build_dist.py
if errorlevel 1 goto fail

if /i "%~1"=="exe" (
    echo.
    echo [2/2] Building standalone exe...
    call "dist\SysPy\build_exe.bat"
)

echo.
echo  Done.
echo    kit : dist\SysPy\
echo    zip : SysPy.zip
pause
exit /b 0

:fail
echo.
echo  BUILD FAILED.
pause
exit /b 1