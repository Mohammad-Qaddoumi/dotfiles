# Log outputs to a file
$scriptDirectory = Split-Path -Parent $PSCommandPath
$logFile = "$scriptDirectory\LogFile.txt"
Start-Transcript -Path $logFile -Append

Write-Host "Start the script testing"
Write-Host "===================================`n`n"


$program = "Git.Git"
try {
    $installArgs = "install --id $program --accept-package-agreements --accept-source-agreements"
    $process = Start-Process -FilePath "winget" -ArgumentList $installArgs -NoNewWindow -PassThru -Wait
    
    # Check the exit code of the process
    $exitCode = $process.ExitCode
    Write-Output "Exit Code: $exitCode"
    
    if ($exitCode -eq 0) {
        # Move the cursor up one line and clear it
        Write-Host "`e[1A`e[K" -NoNewline
        Write-Host "Successfully Installed (ID): $program"
    } else {
        Write-Host "Failed to install $program. Exit code: $exitCode"
    }
} catch {
    Write-Output "An error occurred while attempting to install $program. Error: $_"
}



Stop-Transcript

# Pause to allow viewing of the script output
Pause
