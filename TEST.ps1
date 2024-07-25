function CheckIfTheUserWantToContinue {
    $Prompt = "The Program is already installed. Do you want to reinstall it`? ``(y/n``) :" 
    $TimeoutSeconds = 7
    $DefaultValue  = "n"
    $userInput = $DefaultValue
    $OutputFile = "$env:TEMP\userinput.txt"
    
    # Create a job for the timeout
    $timeoutJob = Start-Job -ScriptBlock {
        param ($timeout, $defaultValue)
        Start-Sleep -Seconds $timeout
        return $defaultValue
    } -ArgumentList $TimeoutSeconds, $DefaultValue
    
    $command = "Write-Host `"$Prompt `" -NoNewline;`$UserInput = Read-Host;if ([string]::IsNullOrWhiteSpace(`$UserInput)) {`$UserInput = $DefaultValue}`$UserInput | Out-File -FilePath $OutputFile -NoNewline"
    
    # Start the process with the command
    $process = Start-Process powershell.exe -NoNewWindow -PassThru -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$command`""
    
    while ($true) {
        if($process.HasExited){
            if (Test-Path $OutputFile) {
                $userInput = Get-Content $OutputFile -Raw
            }
            break
        }
        if (Get-Job -Id $timeoutJob.Id | Where-Object { $_.State -eq 'Completed' }) {
            Stop-Process -Id $process.Id  -PassThru -Force
            $userInput = $DefaultValue
            Write-Host "Timed out. Using default value: $userInput"
            break
        }
        Start-Sleep -Milliseconds 100
    }
    
    Stop-Job -Id $timeoutJob.Id | Out-Null
    Remove-Job -Id $timeoutJob.Id | Out-Null
    
    # Clean up the temporary file
    if (Test-Path $OutputFile) {
        Remove-Item $OutputFile
    }
    
    Start-Sleep -Seconds 2
    return $userInput
}

$userInput = CheckIfTheUserWantToContinue
if ($userInput -ne "y") {
    Write-Output "Installation aborted."
}
else {
    Write-Output "Continue"
}
