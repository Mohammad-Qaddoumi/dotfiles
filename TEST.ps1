Write-Host "I made it"
Write-Host $PSCommandPath

# Remove the scheduled task
if (Get-ScheduledTask -TaskName "ContinueInstallation" -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName "ContinueInstallation" -Confirm:$false
}


if ($args[0] -eq "continue") {
    Write-Host "continue is passed"
    Write-Host "Running after reboot"
}
else{
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
}


Pause
