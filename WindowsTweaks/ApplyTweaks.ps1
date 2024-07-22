# Define the path to the JSON file
$jsonFilePath = ".\Tweaks.json"

# Read the JSON file
$jsonContent = Get-Content -Path $jsonFilePath -Raw | ConvertFrom-Json

# Extract the WPFTweaks array
$wpftweaks = $jsonContent.WPFTweaks

# Function Definitions
function Apply-WifiTweak {
    Write-Output "Applying WiFi Tweak..."
    # Insert WiFi tweak commands here
}

function Apply-HomeTweak {
    Write-Output "Applying Home Tweak..."
    # Insert Home tweak commands here
}

function Apply-StorageTweak {
    Write-Output "Applying Storage Tweak..."
    # Insert Storage tweak commands here
}

function Apply-ConsumerFeaturesTweak {
    Write-Output "Disabling Consumer Features..."
    Disable-WindowsOptionalFeature -FeatureName "ConsumerExperience" -Online
}

function Apply-DVRTweak {
    Write-Output "Disabling DVR..."
    Disable-GameDVR
}

function Apply-TeleTweak {
    Write-Output "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Force
}

function Apply-DisplayTweak {
    Write-Output "Adjusting Display Settings..."
    # Insert Display tweak commands here
}

function Apply-AHTweak {
    Write-Output "Applying AH Tweak..."
    # Insert AH tweak commands here
}

function Apply-EndTaskOnTaskbarTweak {
    Write-Output "Enabling End Task on Taskbar..."
    # Insert End Task on Taskbar tweak commands here
}

function Apply-LocTweak {
    Write-Output "Disabling Location Services..."
    # Insert Location Services tweak commands here
}

function Apply-TeredoTweak {
    Write-Output "Disabling Teredo..."
    # Insert Teredo tweak commands here
}

function Apply-DeleteTempFilesTweak {
    Write-Output "Deleting Temporary Files..."
    # Insert Delete Temporary Files tweak commands here
}

function Apply-Powershell7Tweak {
    Write-Output "Installing PowerShell 7..."
    iex "& { $(irm https://aka.ms/install-powershell.ps1) }"
}

# Function to apply tweaks based on their name
function Apply-Tweak {
    param (
        [string]$tweakName
    )

    switch ($tweakName) {
        "WPFTweaksWifi" { Apply-WifiTweak }
        "WPFTweaksHome" { Apply-HomeTweak }
        "WPFTweaksStorage" { Apply-StorageTweak }
        "WPFTweaksConsumerFeatures" { Apply-ConsumerFeaturesTweak }
        "WPFTweaksDVR" { Apply-DVRTweak }
        "WPFTweaksTele" { Apply-TeleTweak }
        "WPFTweaksDisplay" { Apply-DisplayTweak }
        "WPFTweaksAH" { Apply-AHTweak }
        "WPFTweaksEndTaskOnTaskbar" { Apply-EndTaskOnTaskbarTweak }
        "WPFTweaksLoc" { Apply-LocTweak }
        "WPFTweaksTeredo" { Apply-TeredoTweak }
        "WPFTweaksDeleteTempFiles" { Apply-DeleteTempFilesTweak }
        "WPFTweaksPowershell7" { Apply-Powershell7Tweak }
        default { Write-Output "Unknown tweak: $tweakName" }
    }
}

# Apply each tweak
foreach ($tweak in $wpftweaks) {
    Apply-Tweak -tweakName $tweak
}
