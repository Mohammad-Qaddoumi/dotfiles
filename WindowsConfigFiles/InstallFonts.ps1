# Function to get the latest release URL for MesloLGS Nerd Font from GitHub
function Get-LatestMesloLGSFontUrl {
    $apiUrl = "https://api.github.com/repos/ryanoasis/nerd-fonts/releases/latest"
    $releaseInfo = Invoke-RestMethod -Uri $apiUrl -Headers @{"User-Agent" = "PowerShell"}
    $asset = $releaseInfo.assets | Where-Object { $_.name -eq "Meslo.zip" }
    return $asset.browser_download_url
}

# Get the latest MesloLGS Nerd Font URL
$fontUrl = Get-LatestMesloLGSFontUrl
if (-not $fontUrl) {
    Write-Output "Could not retrieve the latest MesloLGS Nerd Font URL."
    exit
}

# Define the destination path for the downloaded zip file
$zipFilePath = "$env:TEMP\Meslo.zip"
# Define the extraction path
$extractPath = "$env:TEMP\MesloNerdFont"

# Download the font zip file
Invoke-WebRequest -Uri $fontUrl -OutFile $zipFilePath

# Create the extraction directory if it does not exist
if (-not (Test-Path -Path $extractPath)) {
    New-Item -ItemType Directory -Path $extractPath
}

# Extract the zip file
Expand-Archive -Path $zipFilePath -DestinationPath $extractPath -Force

# Get the list of font files
$fontFiles = Get-ChildItem -Path $extractPath -Filter "*.ttf"

# Define the system fonts directory
$fontsFolder = "$env:SystemRoot\Fonts"

# Copy the font files to the system fonts directory
foreach ($fontFile in $fontFiles) {
    $fontFilePath = $fontFile.FullName
    $fontFileName = $fontFile.Name
    $destinationPath = Join-Path -Path $fontsFolder -ChildPath $fontFileName
    Copy-Item -Path $fontFilePath -Destination $destinationPath -Force

    # Register the font in the system
    $fontRegKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
    $fontRegName = $fontFileName
    New-ItemProperty -Path $fontRegKey -Name $fontRegName -Value $fontFileName -PropertyType String -Force
}

# Clean up
Remove-Item -Path $zipFilePath -Force
Remove-Item -Path $extractPath -Recurse -Force

Write-Output "Meslo LG Nerd Font installed successfully."
