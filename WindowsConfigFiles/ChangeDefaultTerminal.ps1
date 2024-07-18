# Define the registry path for the console settings
$regPath = "HKCU:\Console"

# Define the key and value for setting the default terminal
$regKey = "ForceV2"
$regValue = 1

# Check if the registry key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $regKey -Value $regValue -Force

# Inform the user
Write-Output "Default terminal has been set to Windows Terminal."
