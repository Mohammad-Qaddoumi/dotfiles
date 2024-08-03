# TODO: Implement this
# function Update-ProgramWinget {
#     <#
#     .SYNOPSIS
#         This will update all programs using Winget
#     #>
#     [ScriptBlock]$wingetinstall = {
#         winget upgrade --all --accept-source-agreements --accept-package-agreements --scope=machine --silent
#     }
#     Start-Process -Verb runas powershell -ArgumentList "-command invoke-command -scriptblock {$wingetinstall} -argumentlist '$($ProgramsToInstall -join ",")'" -PassThru
# }

# Write-Host "Updating All Winget Programs`n" -ForegroundColor Green
# Update-ProgramWinget


# Function to upgrade all installed winget apps
function Update-ProgramWinget {
    # Get a list of all installed winget apps
    $apps = winget list | Select-Object -Skip 1 | ForEach-Object {
        $_.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)[0]
    }

    # Get the total number of apps to upgrade
    $totalApps = $apps.Count

    # Loop through each app and upgrade
    $index = 0
    foreach ($app in $apps) {
        # Update progress
        Write-Progress -PercentComplete (($index / $totalApps) * 100) -Status "Upgrading apps" -CurrentOperation "Upgrading $app"

        # Upgrade the app
        # `-Accept-source-agreements` and `-Accept-package-agreements` are optional flags; add them if needed
        winget upgrade $app -h --accept-source-agreements --accept-package-agreements | Out-Host

        # Increment index
        $index++
    }

    # Final progress update
    Write-Progress -PercentComplete 100 -Status "Upgrading apps" -CurrentOperation "Completed"
}

# Call the function to start the upgrade process
Update-ProgramWinget
