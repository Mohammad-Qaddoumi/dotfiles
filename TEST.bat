@echo off

SET "mycommand=Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine"

powershell -NoProfile -Command "& {Start-Process powershell -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', \"%mycommand%\" -Verb RunAs}"


if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell script with admin rights.
    pause
    exit /b 1
)

