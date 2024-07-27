$scriptDirectory = Split-Path -Parent $PSCommandPath
Write-Host "$scriptDirectory\logfile.log"
cd $pwd
Set-Location $(Get-Location)
cd $pwd

"-ExecutionPolicy Bypass -File `"$PSCommandPath`" continue"
"-ExecutionPolicy Bypass -Command `"Set-Location `"$(Get-Location)`"; & `"$PSCommandPath`" continue;`""