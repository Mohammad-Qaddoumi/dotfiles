@echo off
SET scriptFileName=%~n0
SET scriptFolderPath=%~dp0
SET powershellScriptFileName=%scriptFileName%.ps1
SET "mycommand=Set-Location '%scriptFolderPath%' ; .\%powershellScriptFileName%"

REM run powershell script WITH THE SAME NAME
:: Check if PowerShell 7 (pwsh) is installed
where pwsh >nul 2>&1
if %errorlevel%==0 (
    echo PowerShell 7 found. Starting PowerShell 7...
    pwsh -NoProfile -Command "& {Start-Process pwsh -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand%\" -Verb RunAs}"
)
else (
    echo PowerShell 7 not found. Starting built-in Windows PowerShell...
    powershell -NoProfile -Command "& {Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand%\" -Verb RunAs}"
)

if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell 7 script with admin rights.
    pause
    exit /b 1
)
