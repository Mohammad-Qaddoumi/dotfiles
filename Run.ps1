# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Output "================================================================`n"
    Write-Output "Run the script with Admin rights`n"
    Write-Output "Change Excution Policy by running : `n"
    Write-Output "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine`n"
    Write-Output "================================================================`n"

    if ($args[0] -eq "continue") {
        Start-Process powershell -Verb runAs -ArgumentList "-ExecutionPolicy Bypass -File `".\Run.ps1`" continue"
    }
    else{
        Start-Process powershell -Verb runAs -ArgumentList "-ExecutionPolicy Bypass -File `".\Run.ps1`""
    }

    Write-Warning "Exiting ..."
    pause
    exit
}

# Function to continue after reboot
function Resume-AfterReboot {
    # Remove the scheduled task
    if (Get-ScheduledTask -TaskName "ContinueInstallation" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
    }
    # Run install_PS_and_WT.ps1
    & "$PSScriptRoot\PreRequisite\install_PS_WT_Git.ps1"

    # Launch Start.ps1 in the new PowerShell (pwsh)
    Start-Process pwsh -ArgumentList "-ExecutionPolicy Bypass -File `"$PSScriptRoot\Start.ps1`""
}

# Check if we're continuing after a reboot
if ($args[0] -eq "continue") {
    Resume-AfterReboot
    exit
}

# Run install_winget.ps1 with -Force parameter
& "$PSScriptRoot\PreRequisite\install_winget.ps1" -Force

# Wait for 5 seconds
Start-Sleep -Seconds 5

if (Get-ScheduledTask -TaskName "ContinueInstallation" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
}
# Create a scheduled task to continue after reboot
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`" continue"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "ContinueInstallation" -Action $action -Trigger $trigger -Principal $principal -Force
# Add this after the Register-ScheduledTask line
if ($?) {
    Write-Host "Scheduled task created successfully"
} else {
    Write-Host "Failed to create scheduled task. Error: $($Error[0])"
}

Write-Host "Do you want to reboot(recommended)? (y/n)" -NoNewline
$userInput = Read-Host
if ($userInput -ne "y") {
    Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
    Resume-AfterReboot
    exit
}
else{
    # Reboot the system
    Restart-Computer -Force
}