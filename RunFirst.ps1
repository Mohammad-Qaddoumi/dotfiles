# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Output "================================================================`n"
    Write-Output "Run the script with Admin rights`n"
    Write-Output "Change Execution Policy by running : `n"
    Write-Output "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine`n"
    Write-Output "================================================================`n"

    # $PSCommandPath : Contains the full path and filename of the script that's being run
    try {
        if ($args[0] -eq "continue") {
            Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd `"$pwd`"; & `"$PSCommandPath`" continue;`"" -ErrorAction Stop
        }
        else {
            Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd `"$pwd`"; & `"$PSCommandPath`";`"" -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Failed to start PowerShell with admin rights. Error: $_"
        pause
        exit 1
    }

    Write-Warning "Exiting ..."
    Start-Sleep -Seconds 5
    exit
}

# Function to continue after reboot
function Resume-AfterReboot {
    # Remove the scheduled task
    if (Get-ScheduledTask -TaskName "ContinueInstallation" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
    }
    # Run install_PS_and_WT.ps1
    $installScript = Join-Path $PSScriptRoot "PreRequisite\install_PS_WT_Git.ps1"
    if (Test-Path $installScript) {
        & $installScript
    }
    else {
        Write-Error "Cannot find script: $installScript"
        pause
        exit 1
    }

    # Launch RunSecond.ps1 in the new PowerShell (pwsh)
    $startScript = Join-Path $PSScriptRoot "RunSecond.ps1"
    if (Test-Path $startScript) {
        Start-Process pwsh -ArgumentList "-ExecutionPolicy Bypass -File `"$startScript`""
    }
    else {
        Write-Error "Cannot find script: $startScript"
        pause
        exit 1
    }
}

# Check if we're continuing after a reboot
if ($args[0] -eq "continue") {
    Resume-AfterReboot
    exit
}

# Run install_winget.ps1 with -Force parameter
$wingetScript = Join-Path $PSScriptRoot "PreRequisite\install_winget.ps1"
if (Test-Path $wingetScript) {
    & $wingetScript -Force
}
else {
    Write-Error "Cannot find script: $wingetScript"
    pause
    exit 1
}

# Wait for 5 seconds
Start-Sleep -Seconds 5

if (Get-ScheduledTask -TaskName "ContinueInstallation" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
}

# Create a scheduled task to continue after reboot
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$PSCommandPath`" continue"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "ContinueInstallation" -Action $action -Trigger $trigger -Principal $principal -Force
    Write-Host "Scheduled task created successfully"
}
catch {
    Write-Error "Failed to create scheduled task. Error: $_"
    pause
    exit 1
}

# TODO: fix this
do {
    $userInput = Read-Host "`nDo you want to reboot (recommended)? (y/n)"
    $userInput = $userInput.ToLower()
} while ($userInput -notmatch '^(y|n|yes|no)$')

if ($userInput -eq 'y' -or $userInput -eq 'yes') {
    Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
    Resume-AfterReboot
    exit
}

# Reboot the system
Restart-Computer -Force
