[CmdletBinding()]
param (
    [string]$Prompt,
    [string]$DefaultValue
)

Write-Host $Prompt -NoNewline

$UserInput = Read-Host
$env:UserInput = $UserInput
