Write-Host "================================================================`n" -Foregroundcolor Red
Write-Host "Run the script in any powershell with Admin rights`n" -Foregroundcolor Red
Write-Host "Change Excution Policy by running : `n" -Foregroundcolor Red
Write-Host "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine`n" -Foregroundcolor Red
Write-Host "================================================================`n" -Foregroundcolor Red

# TODO: make sure this script runs with pwsh not powershell
# Check if running with admin rights
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Ensure the script runs with admin rights
if (-not (Test-IsAdmin)) {
    Write-Host "This script must be run as an administrator."
    exit
}

#region Define the scripts
#  and their descriptions
$scripts = @(
    @{ Name = ".\PreRequisite\RunAllPreRequisite.ps1"; Description = "Install all pre requisite"; Parameter = ""; SleepTime = 0; MessageAfter = "You may need to restart if did not work"}
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
