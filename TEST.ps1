# Log outputs to a file
$scriptDirectory = Split-Path -Parent $PSCommandPath
$logFile = "$scriptDirectory\LogFile.txt"
Start-Transcript -Path $logFile -Append

Write-Host "Start the script testing"
Write-Host "===================================`n`n"



$Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
Set-ItemProperty -Path $Theme -Name AppsUseLightTheme -Value 1
Set-ItemProperty -Path $Theme -Name SystemUsesLightTheme -Value 1




Stop-Transcript

# Pause to allow viewing of the script output
Pause
