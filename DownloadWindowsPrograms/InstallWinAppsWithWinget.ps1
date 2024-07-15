# Enable detailed script tracing
Set-PSDebug -Trace 2

# Path to the file containing the list of programs
$filePath = ".\WINGET_Programs.txt"

# Function to check if winget is installed
function Test-Winget {
    Write-Output "Checking if winget is installed..."
    $wingetPath = (Get-Command winget -ErrorAction SilentlyContinue).Path
    if ($null -eq $wingetPath) {
        Write-Output "winget is not installed. Installing winget..."
        Install-Winget
    } else {
        Write-Output "winget is already installed at $wingetPath."
    }
}

# Function to install winget
function Install-Winget {
    # Download the latest winget installer
    $wingetInstallerUrl = "https://aka.ms/getwinget"
    $wingetInstallerPath = "$env:TEMP\wingetInstaller.msixbundle"
    Write-Output "Downloading winget installer from $wingetInstallerUrl..."
    Invoke-WebRequest -Uri $wingetInstallerUrl -OutFile $wingetInstallerPath
    
    # Install winget
    Write-Output "Installing winget from $wingetInstallerPath..."
    Add-AppxPackage -Path $wingetInstallerPath
    
    # Verify installation
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Output "winget installed successfully."
    } else {
        Write-Output "Failed to install winget."
        exit 1
    }
}

# Function to check if a program is installed
function Test-ProgramInstalled {
    param (
        [string]$program
    )
    Write-Output "Checking if $program is already installed..."
    $installedPrograms = winget list | Select-String -Pattern $program
    if ($installedPrograms) {
        Write-Output "$program is already installed."
        return $true
    } else {
        Write-Output "$program is not installed."
        return $false
    }
}

# Function to install a program using winget
function Install-Program {
    param (
        [string]$program
    )
    if (Test-ProgramInstalled -program $program) {
        Write-Output "Skipping installation of $program as it is already installed."
    } else {
        Write-Output "Attempting to install $program..."
        try {
            $installResult = winget install --id $program --silent --accept-package-agreements --accept-source-agreements -Wait
            if ($installResult.ExitCode -eq 0) {
                Write-Output "$program installed successfully."
            } else {
                Write-Output "Failed to install $program. Exit code: $($installResult.ExitCode)"
            }
        } catch {
            Write-Output "An error occurred while attempting to install $program. Error: $_"
        }
    }
}

# Main script execution
Write-Output "Starting script execution..."

# Ensure winget is installed
Test-Winget

# Read the list of programs from the file
Write-Output "Reading list of programs from $filePath..."
$programs = Get-Content -Path $filePath

# Install each program
foreach ($program in $programs) {
    Install-Program -program $program
}

Write-Output "Script execution completed."

# Disable detailed script tracing
Set-PSDebug -Off