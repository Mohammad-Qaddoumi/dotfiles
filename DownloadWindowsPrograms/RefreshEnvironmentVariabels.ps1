# Reload environment variables from the system (user and machine)
[System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::User).GetEnumerator() | ForEach-Object {
    [System.Environment]::SetEnvironmentVariable($_.Key, $_.Value, 'Process')
}

[System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine).GetEnumerator() | ForEach-Object {
    [System.Environment]::SetEnvironmentVariable($_.Key, $_.Value, 'Process')
}

# Display refreshed environment variables
Write-Out "Refreshed environment variables:"
Get-ChildItem Env:
Write-Out "Done"
