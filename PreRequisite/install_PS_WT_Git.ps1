$PROGRAMS_ID = @(
    "Microsoft.PowerShell"
    "Microsoft.WindowsTerminal"
    "Git.Git"
)

foreach($program in $PROGRAMS_ID){
    $installArgs = "install --exact --id $program  --source winget --accept-package-agreements --accept-source-agreements"
    $process = Start-Process -FilePath "winget" -ArgumentList $installArgs -NoNewWindow -PassThru
    $process.WaitForExit()
}

Write-Output "`n================================================================"
Write-Output "`n   === Refresh Environment Variabels : ===`n"
& .\DownloadWindowsPrograms\RefreshEnvironmentVariabels.ps1
