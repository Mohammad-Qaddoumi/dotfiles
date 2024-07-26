@echo off
SET scriptFileName=TEST.ps1
SET scriptFolderPath=%~dp0
SET powershellScriptFileName=%scriptFileName%
SET "mycommand=Set-Location '%scriptFolderPath%' ; .\%powershellScriptFileName%"

REM Start PowerShell with elevated privileges and run the script
pwsh -NoProfile -Command "& {Start-Process pwsh -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand%\" -Verb RunAs}"

if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell 7 script with admin rights.
    pause
    exit /b 1
)
