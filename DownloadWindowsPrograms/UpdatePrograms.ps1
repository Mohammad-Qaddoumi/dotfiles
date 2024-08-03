function Update-ProgramWinget {
    <#
    .SYNOPSIS
        This will update all programs using Winget
    #>
    [ScriptBlock]$wingetinstall = {
        winget upgrade --all --accept-source-agreements --accept-package-agreements --scope=machine --silent
    }
    Start-Process -Verb runas powershell -ArgumentList "-command invoke-command -scriptblock {$wingetinstall} -argumentlist '$($ProgramsToInstall -join ",")'" -NoNewWindow -Wait
}

Write-Host "Updating All Winget Programs`n" -ForegroundColor Green
Update-ProgramWinget
