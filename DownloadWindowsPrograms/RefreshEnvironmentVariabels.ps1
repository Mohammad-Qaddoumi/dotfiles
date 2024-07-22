[System.Environment]::GetEnvironmentVariables().GetEnumerator() | ForEach-Object {
    $name = $_.Key
    $value = $_.Value
    [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
}

# Display refreshed environment variables
Get-ChildItem Env:
