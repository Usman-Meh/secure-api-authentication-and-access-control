@echo off
REM ============================================
REM  Construction Equipment Rental API - Start Application
REM  Windows Script
REM ============================================

echo ============================================
echo  Construction Equipment Rental API (hardened)
echo  Starting Application...
echo ============================================
echo.

REM Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Navigate to the script's directory
cd /d "%~dp0"

REM Install dependencies if needed
echo Installing dependencies...
pip install -r requirements.txt --quiet
echo.

REM Start the Flask application
echo Starting Flask server on http://localhost:5000
echo Press Ctrl+C to stop the server.
echo.
python app_solution.py
pause
