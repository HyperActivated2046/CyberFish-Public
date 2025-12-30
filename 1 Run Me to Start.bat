@echo off
setlocal
title CyberFish Launcher
cls

echo =========================================================
echo         CyberFish - Phishing Simulator by TP066880
echo =========================================================
echo.

echo [INFO] Loading...
echo.
echo [##........] 20%% - Checking for Python...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo         Please install Python 3.10+ from https://python.org
    echo         and make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b
)

echo [####......] 40%% - Checking virtual environment...
if not exist "venv\Scripts\activate.bat" (
    echo [####......] 45%% - Creating virtual environment ^(this might take a moment^)...
    python -m venv venv >nul
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b
    )
)

echo [######....] 60%% - Installing dependencies (this might take a moment)...
call "venv\Scripts\activate.bat"
pip install -r resources\requirements.txt > pip_install.log 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to install dependencies. See pip_install.log for details.
    echo.
    type pip_install.log
    pause
    exit /b
)

echo [########..] 80%% - Cleaning up...
del pip_install.log >nul 2>&1

echo [##########] 100%% - Done.
echo.
echo [INFO] Starting CyberFish...
timeout /t 1 /nobreak > nul
cls

python resources/banner.py
python CyberFish.py

if %errorlevel% neq 0 (
    echo.
    echo [CRITICAL] The application exited with an error code: %errorlevel%.
    pause
)

echo.

echo [INFO] CyberFish has closed.

endlocal
