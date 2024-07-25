# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Output "================================================================`n"
    Write-Output "Run the script with Admin rights`n"
    Write-Output "Change Excution Policy by running : `n"
    Write-Output "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine`n"
    Write-Output "================================================================`n"
    Write-Warning "Exiting ..."
    pause
    exit
}

# Function to continue after reboot
function Continue-AfterReboot {
    # Remove the scheduled task
    Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false

    # Run install_PS_and_WT.ps1
    & "$PSScriptRoot\PreRequisite\install_PS_and_WT.ps1"

    # Launch Start.ps1 in the new PowerShell (pwsh)
    Start-Process pwsh -ArgumentList "-ExecutionPolicy Bypass -File `"$PSScriptRoot\Start.ps1`""
}

# Check if we're continuing after a reboot
if ($args[0] -eq "continue") {
    Continue-AfterReboot
    exit
}

# Run install_winget.ps1 with -Force parameter
& "$PSScriptRoot\PreRequisite\install_winget.ps1" -Force

# Wait for 5 seconds
Start-Sleep -Seconds 5

# Create a scheduled task to continue after reboot
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`" continue"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "ContinueInstallation" -Action $action -Trigger $trigger -Principal $principal -Force

Write-Host "Do you want to reboot(recommended)? (y/n)" -NoNewline
$userInput = Read-Host
if ($userInput -ne "y") {
    Continue-AfterReboot
}
else{
    # Reboot the system
    Restart-Computer -Force
}