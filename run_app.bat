@echo off
title CyberScope Network Port Scanner Launcher
color 0b
cls
echo ===============================================================
echo        CYBERSCOPE NETWORK PORT SCANNER & SERVICE DETECTOR
echo ===============================================================
echo.
echo   Select how you would like to run the application:
echo.
echo     [1] Interactive Web App (Recommended - Opens in Browser)
echo     [2] Desktop GUI App (Native Windows Window)
echo     [3] Command Line Scanner (CLI)
echo     [4] Open Project Folder in File Explorer
echo     [5] Exit
echo.
echo ===============================================================
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    echo.
    echo Starting Web Application on http://localhost:5000 ...
    python web_app.py
    pause
    exit
)

if "%choice%"=="2" (
    echo.
    echo Starting Desktop GUI App ...
    python app_gui.py
    exit
)

if "%choice%"=="3" (
    echo.
    echo Running Command Line Scanner on localhost (common ports)...
    python scanner.py -t 127.0.0.1 -p common
    pause
    exit
)

if "%choice%"=="4" (
    explorer .
    exit
)

if "%choice%"=="5" (
    exit
)

echo Invalid choice.
pause
