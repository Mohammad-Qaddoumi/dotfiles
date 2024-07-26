@echo off
SET scriptFileName=TEST.ps1
SET scriptFolderPath=%~dp0
SET powershellScriptFileName=%scriptFileName%
SET "mycommand=Set-Location '%scriptFolderPath%' ; .\%powershellScriptFileName%"
SET "TaskName=ContinueInstallation"
SET "mycontinue=continue"

schtasks /query /tn "%TaskName%" >nul 2>&1

if %ERRORLEVEL% equ 0 (
    echo The "%TaskName%" task exists.
    powershell -NoProfile -Command "& {Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand% %mycontinue% \" -Verb RunAs}"
) else (
    echo The "%TaskName%" task does not exist.
    powershell -NoProfile -Command "& {Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand%\" -Verb RunAs}"
)

if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell script with admin rights.
    pause
    exit /b 1
)
