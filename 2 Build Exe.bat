@echo off
setlocal
title CyberFish Builder
cls

echo =========================================================
echo              CyberFish - Executable Builder
echo =========================================================
echo.
echo [INFO] This script will create a standalone 'CyberFish.exe' file.
echo [INFO] This allows you to run the app on computers without Python installed.
echo.

echo [##........] 20%% - Checking environment...
if not exist "venv\Scripts\activate.bat" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
)
call "venv\Scripts\activate.bat"

echo [####......] 40%% - Installing PyInstaller and Requirements...
python -m pip install pyinstaller -r resources\requirements.txt > build_install.log 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to install build requirements. Check build_install.log.
    pause
    exit /b
)

echo [######....] 60%% - Preparing build directories...
if not exist "Build" mkdir Build
if not exist "Release" mkdir Release

echo [########..] 80%% - Building CyberFish.exe (this takes a minute)...

REM Build command options:
REM --distpath "Release": Puts the final .exe in a folder named Release
REM --workpath "Build\temp": Puts temporary build files in Build\temp
REM --specpath "Build": Puts the .spec file in Build
REM --noconfirm: Overwrite existing files
REM --onefile: Create a single .exe
REM --windowed: No console window
REM --clean: Clean cache before building

pyinstaller --noconfirm --onefile --windowed --clean --name "CyberFish" --add-data "%~dp0resources;resources" --hidden-import "sv_ttk" --hidden-import "cryptography" --collect-all "reportlab" --distpath "Release" --workpath "Build\temp" --specpath "Build" CyberFish.py > build_process.log 2>&1

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed. See build_process.log for details.
    echo.
    type build_process.log | findstr "Error"
    pause
    exit /b
)

echo [##########] 100%% - Build Complete!
echo.
echo =====================================================================
echo                     [SUCCESS] Your app is ready.
echo.
echo                   Location:  Release\CyberFish.exe
echo.
echo You can delete the 'Build' folder and logs if you want to save space.
echo =====================================================================
echo.
pause
endlocal
