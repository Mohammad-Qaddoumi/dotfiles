﻿# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Output "================================================================`n" -Foregroundcolor Red
    Write-Output "Run the script with Admin rights`n" -Foregroundcolor Red
    Write-Output "Change Execution Policy by running : `n" -Foregroundcolor Red
    Write-Output "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine`n" -Foregroundcolor Red
    Write-Output "================================================================`n" -Foregroundcolor Red

    $pwshPath = Get-Command pwsh -ErrorAction SilentlyContinue
    $RunningPowerShell = "PowerShell"
    if($pwshPath){
        $RunningPowerShell = "pwsh"
    }

    # $PSCommandPath : Contains the full path and filename of the script that's being run
    try {
        Start-Process $RunningPowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"Set-Location `"$(Get-Location)`"; & `"$PSCommandPath`";`"" -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to start PowerShell with admin rights. Error: $_"
        pause
        exit 1
    }

    Write-Host "Exiting ..."
    Start-Sleep -Seconds 5
    exit 0
}

# If not running with powershell7 and powershell7 is installed
$pwshPath = Get-Command pwsh -ErrorAction SilentlyContinue
$isBuiltInWindowsPowerShell = ($PSVersionTable.PSEdition -eq 'Desktop')
if($pwshPath -and -not $isBuiltInWindowsPowerShell){
    Start-Process pwsh -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"Set-Location `"$(Get-Location)`"; & `"$PSCommandPath`";`"" -ErrorAction Stop
    Write-Host "Opening with pwsh`nExiting ..."
    Start-Sleep -Seconds 5
    exit 0
}

#region Define the scripts
#  and their descriptions
$scripts = @(
    @{ Name = ".\PreRequisite\Install_winget.ps1"; Description = "Install winget"; Parameter = ""; SleepTime = 0; MessageAfter = "You may need to restart if did not work"}
    @{ Name = ".\PreRequisite\install_PS_WT_Git.ps1"; Description = "Install powershell 7, windows terminal, AND git"; Parameter = ""; SleepTime = 0; MessageAfter = ""}
    @{ Name = ".\PreRequisite\SET_EP.ps1"; Description = "Set Execution Policy"; Parameter = ""; SleepTime = 0; MessageAfter = ""}
    @{ Name = ".\DownloadWindowsPrograms\InstallWinAppsWithWinget.ps1"; Description = "Bulk install windows progarm"; Parameter = ""; SleepTime = 0; MessageAfter = "" }
    @{ Name = ".\DownloadWindowsPrograms\UpdatePrograms.ps1"; Description = "Bulk Upgrade windows progarm"; Parameter = ""; SleepTime = 0; MessageAfter = "" }
    @{ Name = ".\WindowsConfigFiles\SetWT&PS_settings.ps1"; Description = "Set WindowsTerminal & PowerShell Settings"; Parameter = ""; SleepTime = 0; MessageAfter = "" }
    @{ Name = ".\WindowsTweaks\ApplyTweaks.ps1"; Description = "Apply Windows Tweaks"; Parameter = ""; SleepTime = 0; MessageAfter = "You may need to restart if did not work" }
    @{ Name = ".\WindowsCleanupMaintenance\DeleteTempFiles.ps1"; Description = "Delete Temp files"; Parameter = ""; SleepTime = 0; MessageAfter = "" }
    @{ Name = ".\WindowsCleanupMaintenance\Maintenance.ps1"; Description = "Daily Registry Backup AND Create Restore Point"; Parameter = ""; SleepTime = 0; MessageAfter = "" }
    # @{ Name = "Script5.ps1"; Description = "Description of Script 5" },
    # @{ Name = "Script6.ps1"; Description = "Description of Script 6" }
)

#region Display Menu
# and get user choice
function Show-Menu {
    param (
        [string]$prompt = 'Select a script to run:'
    )

    # TODO: make a choice to run everythings.
    # 1. Run all scripts
    Write-Host $prompt
    for ($i = 0; $i -lt $scripts.Count; $i++) {
        Write-Host "$($i + 1). $($scripts[$i].Description)"
    }
    Write-Host "$($scripts.Count + 1). Exit"

    $choice = Read-Host "Enter the number of your choice"
    return [int]$choice
}

# Main logic
#region Excute The Scripts
do {
    $choice = Show-Menu

    if ($choice -gt 0 -and $choice -le $scripts.Count) {
        $scriptToRun = $scripts[$choice - 1].Name
        $scriptParameter = $scripts[$choice - 1].Parameter
        $sleepTime = $scripts[$choice - 1].SleepTime
        $messageAfter = $scripts[$choice - 1].MessageAfter
        $scriptDirectory = Split-Path -Parent $scriptToRun
        $originalDirectory = Get-Location

        if ($scriptDirectory -ne '') {
            Write-Host "`nChanging directory to $scriptDirectory"
            Set-Location $scriptDirectory
        }

        Write-Output "`n================================================================"
        Write-Output "================================================================"
        # TODO: Add Try Catch

        Write-Host "`nRunning $scriptToRun...`n"
        # TODO: $host.ui.RawUI.WindowTitle = """Winget Install"""
        Write-Output "================================================================"
        if ($scriptParameter) {
            $command = "& .\$(Split-Path -Leaf $scriptToRun) $scriptParameter"
            Invoke-Expression $command
        } else {
            & .\$(Split-Path -Leaf $scriptToRun)
        }
        if($messageAfter){
            Write-Host ""
            Write-Warning $messageAfter
        }
        if($sleepTime){
            Start-Sleep -Seconds $sleepTime
        }

        Write-Output "`n================================================================"
        Write-Output "================================================================"

        if ($scriptDirectory -ne '') {
            Write-Host "`nReturning to original directory $originalDirectory`n"
            Set-Location $originalDirectory
            Write-Output "================================================================`n"
        }
    } elseif ($choice -eq $scripts.Count + 1) {
        Write-Host "`nExiting..."
        break
    } else {
        Write-Host "Invalid choice. Please try again."
    }
} while ($true)
#region Exit
Write-Host " _____                       "
Write-Host "(____ \                      "
Write-Host " _   \ \ ___  ____   ____    "
Write-Host "| |   | / _ \|  _ \ / _  )   "
Write-Host "| |__/ / |_| | | | ( (/ /    "
Write-Host "|_____/ \___/|_| |_|\____)   "