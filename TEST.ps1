Write-Host "I made it"

do {
    $userInput = Read-Host "`nDo you want to reboot (recommended)? (y/n)"
    $userInput = $userInput.ToLower()
} while ($userInput -notmatch '^(y|n|yes|no)$')

Write-Host "UserInput : $userInput"

if ($userInput -eq 'y' -or $userInput -eq 'yes') {
    Write-Host "YES"
}
else
{
    Write-Host "NO"
}








Pause
