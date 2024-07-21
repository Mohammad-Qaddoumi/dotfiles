Write-Output "================================================================`n"
Write-Output "Run the script in any powershell with Admin rights`n"
Write-Output "Change Excution Policy by running : `n"
Write-Output "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine`n"
Write-Output "================================================================`n"

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

# Define the scripts and their descriptions(optional)
$scripts = @(
    @{ Name = ".\DownloadWindowsPrograms\InstallWinAppsWithWinget.ps1"; Description = "Bulk install windows progarm " },
    @{ Name = ".\WindowsConfigFiles\SetWT&PS_settings.ps1"; Description = "Set WindowsTerminal & PowerShell Settings " }
    # @{ Name = "Script3.ps1"; Description = "Description of Script 3" },
    # @{ Name = "Script4.ps1"; Description = "Description of Script 4" },
    # @{ Name = "Script5.ps1"; Description = "Description of Script 5" }
)

# Function to display the menu and get user choice
function Show-Menu {
    param (
        [string]$prompt = 'Select a script to run:'
    )

    Write-Host $prompt
    for ($i = 0; $i -lt $scripts.Count; $i++) {
        Write-Host "$($i + 1). $($scripts[$i].Description)"
    }
    Write-Host "$($scripts.Count + 1). Exit"

    $choice = Read-Host "Enter the number of your choice"
    return [int]$choice
}

# Main logic
do {
    $choice = Show-Menu

    if ($choice -gt 0 -and $choice -le $scripts.Count) {
        $scriptToRun = $scripts[$choice - 1].Name
        $scriptDirectory = Split-Path -Parent $scriptToRun
        $originalDirectory = Get-Location

        if ($scriptDirectory -ne '') {
            Write-Host "`nChanging directory to $scriptDirectory"
            Set-Location $scriptDirectory
        }

        Write-Output "`n================================================================"
        Write-Output "================================================================"
        
        Write-Host "`nRunning $scriptToRun...`n"
        Write-Output "================================================================"
        & .\$(Split-Path -Leaf $scriptToRun)

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
