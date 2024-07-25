@echo off

set scriptFileName=%~n0
set scriptFolderPath=%~dp0
set powershellScriptFileName=%scriptFileName%.ps1

powershell -Command "Start-Process powershell -Verb RunAs -ExecutionPolicy Bypass -NoProfile -NoExit -Command `"cd `"%scriptFolderPath%`"; & `".\%powershellScriptFileName%`"`""

if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell script with admin rights.
    pause
    exit /b 1
)
