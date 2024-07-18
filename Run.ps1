# Define the scripts and their descriptions
$scripts = @(
    @{ Name = ".\DownloadWindowsPrograms\InstallWinAppsWithWinget.ps1"; Description = "Bulk install windows progarm " },
    @{ Name = "Script2.ps1"; Description = "Description of Script 2" },
    @{ Name = "Script3.ps1"; Description = "Description of Script 3" }
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
            Write-Host "Changing directory to $scriptDirectory"
            Set-Location $scriptDirectory
        }

        Write-Host "Running $scriptToRun..."
        & .\$(Split-Path -Leaf $scriptToRun)

        if ($scriptDirectory -ne '') {
            Write-Host "Returning to original directory $originalDirectory"
            Set-Location $originalDirectory
        }
    } elseif ($choice -eq $scripts.Count + 1) {
        Write-Host "Exiting..."
        break
    } else {
        Write-Host "Invalid choice. Please try again."
    }
} while ($true)