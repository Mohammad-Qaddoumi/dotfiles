function Test-FontInstalled { return $true} 

# Function to read user input with a timeout using Start-Job and Receive-Job
function Read-HostWithTimeout {
    param (
        [string]$Prompt,
        [int]$TimeoutSeconds,
        [string]$DefaultValue
    )

    # Create a job for the timeout
    $timeoutJob = Start-Job -ScriptBlock {
        param ($timeout, $defaultValue)
        Start-Sleep -Seconds $timeout
        return $defaultValue
    } -ArgumentList $TimeoutSeconds, $DefaultValue

    # Create a job for user input
    $inputJob = Start-Job -ScriptBlock {
        param ($prompt)
        Write-Host $prompt -NoNewline
        return Read-Host
    } -ArgumentList $Prompt

    # Wait for either job to complete
    while ($true) {
        if (Get-Job -Id $inputJob.Id | Where-Object { $_.State -eq 'Completed' }) {
            $userInput = Receive-Job -Id $inputJob.Id
            Stop-Job -Id $timeoutJob.Id | Out-Null
            Remove-Job -Id $timeoutJob.Id | Out-Null
            break
        }
        if (Get-Job -Id $timeoutJob.Id | Where-Object { $_.State -eq 'Completed' }) {
            $userInput = Receive-Job -Id $timeoutJob.Id
            Stop-Job -Id $inputJob.Id | Out-Null
            Remove-Job -Id $inputJob.Id | Out-Null
            break
        }
        Start-Sleep -Milliseconds 100
    }

    # Clean up
    Remove-Job -Id $inputJob.Id | Out-Null
    Remove-Job -Id $timeoutJob.Id | Out-Null

    return $userInput
}

# Check if the font is already installed
if (Test-FontInstalled) {
    $userInput = Read-HostWithTimeout -Prompt "The Meslo LG Nerd Font is already installed. Do you want to reinstall it? (y/n) " -TimeoutSeconds 5 -DefaultValue "n"
    if ($userInput -ne "y") {
        Write-Output "Installation aborted."
        exit
    }
}