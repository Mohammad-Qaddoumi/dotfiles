@echo off
SET scriptFileName=TEST.ps1
SET scriptFolderPath=%~dp0
SET powershellScriptFileName=%scriptFileName%
SET "mycommand=Set-Location '%scriptFolderPath%' ; .\%powershellScriptFileName%"

REM Start PowerShell with elevated privileges and run the script
powershell -NoProfile -Command "& {Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand%\" -Verb RunAs}"

if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell script with admin rights.
    pause
    exit /b 1
)
