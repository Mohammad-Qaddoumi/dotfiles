set scriptFileName=%~n0
set scriptFolderPath=%~dp0
set powershellScriptFileName=%scriptFileName%.ps1

echo "%scriptFolderPath% %powershellScriptFileName%"
set mycommand = "cd \"%scriptFolderPath%\"; \& \".\%powershellScriptFileName%\""
echo %mycommand%
powershell -NoNewWindow -Command "Start-Process powershell -NoNewWindow -Verb RunAs -ExecutionPolicy Bypass -NoProfile -NoExit -Command \"%mycommand%\""

if %ERRORLEVEL% neq 0 (
    echo Failed to start PowerShell script with admin rights.
    pause
    exit /b 1
)
pause