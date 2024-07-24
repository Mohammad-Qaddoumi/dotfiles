$Prompt = "The Program is already installed. Do you want to reinstall it? (y/n) " 
$TimeoutSeconds = 5 
$DefaultValue  = "n"
$userInput = $DefaultValue
$global:UserInput = $DefaultValue

# Create a job for the timeout
$timeoutJob = Start-Job -ScriptBlock {
    param ($timeout, $defaultValue)
    Start-Sleep -Seconds $timeout
    return $defaultValue
} -ArgumentList $TimeoutSeconds, $DefaultValue

# # Create a job for user input
# $inputJob = Start-Job -ScriptBlock {
#     Write-Output "1"
#     param ($prompt, $defaultValue)
#     $scriptParameter = "-prompt `"$prompt`" -defaultValue `"$defaultValue`""
#     $command = "& .\TestInupt.ps1 $scriptParameter"
#     Invoke-Expression $command
#     Write-Output "2"
#     return $env:UserInput

#     # & .\TestInupt.ps1 $prompt $defaultValue

#     # $process = Start-Process -FilePath "powershell" -ArgumentList "-prompt '$prompt' -defaultValue '$defaultValue'" -NoNewWindow -PassThru
#     # $process.WaitForExit()
#     # Write-Output "Exit Code : $($process.ExitCode)"
#     # return $process.ExitCode

#     # Write-Host $prompt -NoNewline
#     # $userInput = $defaultValue
#     # while($true){
#     #     if ($Host.UI.RawUI.KeyAvailable) {
#     #         $userInput = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
#     #     }
#     #     Start-Sleep -Milliseconds 100
#     # }
#     # return $userInput

#     # $answer = Read-Host
#     # return $answer
# } -ArgumentList $Prompt, $DefaultValue

$scriptPath = ".\TestInupt.ps1"

$process = Start-Process powershell.exe -ArgumentList "-NoProfile", "-ExecutionPolicy Bypass", "-File `"$scriptPath`"", "-Prompt `"$Prompt`"", "-DefaultValue `"$DefaultValue`"" -NoNewWindow -PassThru

while ($true) {
    if($process.HasExited){
        Write-Host $global:UserInput
        break
    }
    # if (Get-Job -Id $inputJob.Id | Where-Object { $_.State -eq 'Completed' }) {
    #     $userInput = Receive-Job -Id $inputJob.Id
    #     break
    # }
    if (Get-Job -Id $timeoutJob.Id | Where-Object { $_.State -eq 'Completed' }) {
        Stop-Process -Id $process.Id  -PassThru -Force
        Write-Host "Choosing default (n)"
        $global:UserInput = Receive-Job -Id $timeoutJob.Id
        break
    }
    Start-Sleep -Milliseconds 100
}

# Clean up
# Stop-Job -Id $inputJob.Id | Out-Null
# Remove-Job -Id $inputJob.Id | Out-Null
Stop-Job -Id $timeoutJob.Id | Out-Null
Remove-Job -Id $timeoutJob.Id | Out-Null

Start-Sleep -Seconds 3

if ($global:UserInput -ne "y") {
    Write-Output "Installation aborted."
}
else {
    Write-Output "Continue"
}
