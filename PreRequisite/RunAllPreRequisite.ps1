Write-Output "`nInstalling WinGet`n"
& .\Install_winget.ps1 -Force
Start-Sleep -Seconds 5

Write-Output "`n================================================================"

Write-Output "`nSet Execution Policy`n"
& .\SET_EP.ps1

Write-Output "`n================================================================"

# Installing powershell, windows terminal , and git
Write-Output "`nInstalling powershell, windows terminal , and git`n"
& .\install_PS_WT_Git.ps1

Write-Output "`n================================================================"
Write-Output "`n   === Refresh Environment Variabels : ===`n"
& .\DownloadWindowsPrograms\RefreshEnvironmentVariabels.ps1
