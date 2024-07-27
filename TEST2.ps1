$scriptDirectory = Split-Path -Parent $PSCommandPath
Write-Host "$scriptDirectory\logfile.log"
Set-Location $(Get-Location)

"-ExecutionPolicy Bypass -File `"$PSCommandPath`" continue"
"-ExecutionPolicy Bypass -Command `"Set-Location `"$(Get-Location)`"; & `"$PSCommandPath`" continue;`""