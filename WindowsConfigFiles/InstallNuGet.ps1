# Check if the running PowerShell is the built-in Windows PowerShell
$isBuiltInWindowsPowerShell = ($PSVersionTable.PSEdition -eq 'Desktop')

if ($isBuiltInWindowsPowerShell) {
    Write-Output "This is the built-in Windows PowerShell, Installing NuGet provider...."
    
    # Install NuGet provider
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    
    # Verify installation
    if (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue) {
        Write-Output "NuGet provider installed successfully."
    } else {
        Write-Output "Failed to install the NuGet provider."
    }
} else {
    Write-Output "This is not the built-in Windows PowerShell."
}
