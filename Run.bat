@echo off
:: Check for administrative privileges
:: If not running as admin, relaunch the script with admin rights
>nul 2>&1 set "suppressOutput=1"
set "params=%*"
if not "%1"=="RUNNING" (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"%~f0\" RUNNING %params%' -Verb RunAs"
    exit /b
)

:: Your PowerShell script or commands go here
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { & ".\Start.ps1" }"
