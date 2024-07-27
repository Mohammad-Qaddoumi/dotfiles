# Log outputs to a file
$scriptDirectory = Split-Path -Parent $PSCommandPath
$logFile = "$scriptDirectory\LogFile.txt"
Start-Transcript -Path $logFile -Append

Write-Host "Start the script testing"
Write-Host "===================================`n`n"


$program = "GitHub.cli"
try {
    $installArgs = "install --id $program --accept-package-agreements --accept-source-agreements"
    $process = Start-Process -FilePath "winget" -ArgumentList $installArgs -NoNewWindow -PassThru -Wait
    
    # Check the exit code of the process
    $exitCode = $process.ExitCode
    if ($exitCode -eq 0) {
        Write-Host "Done Installing (ID): $program Exit code: $($exitCode)"
    } else {
        Write-Host "Failed to install $program. Exit code: $($exitCode)"
    }
} catch {
    Write-Output "An error occurred while attempting to install $program. Error: $_"
}



Stop-Transcript

# Pause to allow viewing of the script output
Pause
