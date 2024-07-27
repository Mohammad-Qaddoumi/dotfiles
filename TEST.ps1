Write-Host "I made it"
Write-Host $PSCommandPath

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
            Write-Host "Continue"
            Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd `"$pwd`"; & `"$PSCommandPath`" continue;`"" -ErrorAction Stop
        }
        else {
            Write-Host "No Continue"
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


if ($args[0] -eq "continue") {
    Write-Host "Continue"
}
else {
    Write-Host "No Continue"
}

Write-Host "Runs With Admin Exiting >>>"



Pause
