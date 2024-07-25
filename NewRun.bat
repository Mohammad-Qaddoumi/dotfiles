@echo off

:: Check for admin privileges
>nul 2>&1 set "suppressOutput=1"
set "params=%*"
if not "%1"=="RUNNING" (
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"%~f0\" RUNNING %params%' -Verb RunAs"
    exit /b
)

:: Change directory to the location of the batch file
cd /d "%~dp0"

:: Check if we're continuing after a reboot
if "%1"=="continue" goto continue

:: Run install_winget.ps1 with -Force parameter
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '.\install_winget.ps1' -Force"

:: Wait for 5 seconds
timeout /t 5 /nobreak

:: Create a scheduled task to continue after reboot
schtasks /create /tn "ContinueInstallation" /tr "cmd.exe /c start /min %~dp0%~nx0 continue" /sc onlogon /ru SYSTEM /rl HIGHEST /f

:: Reboot the system
shutdown /r /t 0

exit

:continue
:: Remove the scheduled task
schtasks /delete /tn "ContinueInstallation" /f

:: Run install_PS_and_WT.ps1
powershell -ExecutionPolicy Bypass -File .\install_PS_and_WT.ps1

:: Launch Start.ps1 in the new PowerShell (pwsh)
pwsh -ExecutionPolicy Bypass -Command "& '.\Start.ps1'"

:: Exit the script
exit