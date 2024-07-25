@echo off
:: Check for administrative privileges
:: If not running as admin, relaunch the script with admin rights
>nul 2>&1 set "suppressOutput=1"
set "params=%*"
if not "%1"=="RUNNING" (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"%~f0\" RUNNING %params%' -Verb RunAs"
    exit /b
)

:: Change directory to the location of the batch file
cd /d "%~dp0"

:: TODO: Try installing powershell last version by installing pre requisite script first 
::       then try lunch the main script with pwsh (the new powershell)

:: Your PowerShell script or commands go here
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '.\Start.ps1'"

:: Pause to keep the window open
pause