@echo off
echo ========================================
echo SOAR Playbook Generator - Node.js Setup
echo ========================================
echo.

echo Checking if Node.js is installed...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is NOT installed
    echo.
    echo Opening Node.js download page...
    start https://nodejs.org/en/download/
    echo.
    echo Please download and install the LTS version
    echo After installation, restart your computer and run this script again
    pause
    exit /b 1
) else (
    echo ✅ Node.js is installed
    node --version
    echo.
    echo Checking npm...
    npm --version
    echo.
    echo Installing project dependencies...
    cd /d "%~dp0"
    npm install
    if %errorlevel% neq 0 (
        echo ❌ npm install failed
        pause
        exit /b 1
    )
    echo.
    echo ✅ Dependencies installed successfully
    echo.
    echo Starting SOAR Playbook Generator...
    echo Server will be available at: http://localhost:3000
    echo Press Ctrl+C to stop the server
    echo.
    npm start
)
