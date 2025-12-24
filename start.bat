@echo off
title Proxy Checker - Full Stack

echo ========================================
echo   Proxy Checker Migration PoC
echo   Starting Backend + Frontend
echo ========================================
echo.

:: Kill any existing processes
echo [1/3] Cleaning up old processes...
taskkill /f /im python.exe 2>nul
timeout /t 1 /nobreak >nul

:: Start Backend (this will create port.json in fontend/public)
echo [2/3] Starting Python Backend...
cd /d "%~dp0backend"
start "Backend - Python" cmd /k "python main.py"

:: Wait for backend to create port.json
echo       Waiting for Backend to initialize...
timeout /t 4 /nobreak >nul

:: Start Frontend
echo [3/3] Starting Vue Frontend...
cd /d "%~dp0fontend"
start "Frontend - Vue" cmd /k "npm run dev"

echo.
echo ========================================
echo   All services started!
echo ========================================
echo.
echo   Frontend: http://localhost:5173
echo   Backend:  See Backend window for port
echo.
echo   Press any key to stop all services...
pause >nul

:: Cleanup
echo.
echo Stopping services...
taskkill /f /im python.exe 2>nul
taskkill /f /im node.exe 2>nul
echo Done!
