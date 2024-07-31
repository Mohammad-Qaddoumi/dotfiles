function Enable-DarkMode {
    $DarkMoveValue = 0
    Try{
        Write-Output "Setting Theme to Dart Mode"
        $Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Set-ItemProperty -Path $Path -Name AppsUseLightTheme -Value $DarkMoveValue
        Set-ItemProperty -Path $Path -Name SystemUsesLightTheme -Value $DarkMoveValue
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $DarkMoveValue due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-BingSearch {
    $Enabled = 1
    Try{
        Write-Host "Enable Bing Search"
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        Set-ItemProperty -Path $Path -Name BingSearchEnabled -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Disable-SearchBoxTaskBar {
    $Enabled = 0
    Try{
        Write-Host "Disabling Search Box TaskBar"
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        Set-ItemProperty -Path $Path -Name SearchboxTaskbarMode -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-HiddenFiles {
    $Enabled = 1
    Try{
        Write-Host "Enabling Hidden Files"
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $Path -Name Hidden -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-HideFileExt {
    $Enabled = 0
    Try{
        Write-Host "Enabling Show Files Extention"
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $Path -Name HideFileExt -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-TaskbarAlignment {
    #Switches between Center & Left Taskbar Alignment
    $Enabled = 0 # To the Left
    Write-Host "Making Taskbar Alignment to the Left"
    Try{
        $Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $Path -Name "TaskbarAl" -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Disable-TaskbarWidgets {
    $Enabled = 0
    Write-Host "Disabling Taskbar Widgets"
    Try{
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $Path -Name TaskbarDa -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-TaskView {
    Write-Host "Enabling Task View"
    $Enabled = 1
    Try{
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $Path -Name ShowTaskViewButton -Value $Enabled
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-UltimatePerformance {
    <#
    .SYNOPSIS
        Creates or removes the Ultimate Performance power scheme
    .PARAMETER State
        Indicates whether to enable or disable the Ultimate Performance power scheme
    #>
    $state = "Enable"
    Try{
        # Check if Ultimate Performance plan is installed
        $ultimatePlan = powercfg -list | Select-String -Pattern "Ultimate Performance"
        if($state -eq "Enable"){
            if ($ultimatePlan) {
                Write-Host "Ultimate Performance plan is already installed."
            } else {
                Write-Host "Installing Ultimate Performance plan..."
                powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
                Write-Host "> Ultimate Performance plan installed."
            }

            # Set the Ultimate Performance plan as active
            $ultimatePlanGUID = (powercfg -list | Select-String -Pattern "Ultimate Performance").Line.Split()[3]
            powercfg -setactive $ultimatePlanGUID

            Write-Host "Ultimate Performance plan is now active."
        }
        elseif($state -eq "Disable"){
            if ($ultimatePlan) {
                # Extract the GUID of the Ultimate Performance plan
                $ultimatePlanGUID = $ultimatePlan.Line.Split()[3]

                # Set a different power plan as active before deleting the Ultimate Performance plan
                $balancedPlanGUID = (powercfg -list | Select-String -Pattern "Balanced").Line.Split()[3]
                powercfg -setactive $balancedPlanGUID

                # Delete the Ultimate Performance plan
                powercfg -delete $ultimatePlanGUID

                Write-Host "Ultimate Performance plan has been uninstalled."
                Write-Host "> Balanced plan is now active."
            } else {
                Write-Host "Ultimate Performance plan is not installed."
            }
        }
    } Catch{
        Write-Warning $psitem.Exception.Message
    }
}
function Disable-DeliveryOptimization {
    Write-Host "Disable Delivery Optimization"
    $regValues = @(
        @{
            Name = "DODownloadMode"
            Value = 1
            Type = "DWord"
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
        },
        @{
            Name = "RequestInfoType"
            Value = 0
            Type = "DWord"
            Path = "Registry::HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization"
        },
        @{
            Name = "DownloadMode"
            Value = 0
            Type = "DWord"
            Path = "Registry::HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings"
        },
        @{
            Name = "DownloadModeProvider"
            Value = 8
            Type = "DWord"
            Path = "Registry::HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings"
        }
    )
    Try{
        foreach ($regValue in $regValues) {
            if (!(Test-Path -Path $regValue.Path)) {
                New-Item -Path $regValue.Path -Force | Out-Null
            }
            New-ItemProperty -Path $regValue.Path -Name $regValue.Name -Value $regValue.Value -Type $regValue.Type -Force | Out-Null
        }
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Set-TaskbarIcons {
    Write-Host "Set Taskbar Icons"

    $regPath1 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
    # Create the registry key if it doesn't exist
    if (!(Test-Path -Path $regPath1)) {
        New-Item -Path $regPath1 -Force | Out-Null
    }
    $regPath2 = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins"
    if (!(Test-Path -Path $regPath2)) {
        New-Item -Path $regPath2 -Force | Out-Null
    }
    $regValues = @(
        @{
            Name = "FavoritesResolve"
            Value = [byte[]]@(0x33, 0x03, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x83, 0x00, 0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x18, 0x57, 0x24, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x59, 0xe0, 0x2d, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x5c, 0xf4, 0xe1, 0xfb, 0xd1, 0x61, 0xd8, 0x01, 0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x3a, 0x00, 0x1f, 0x80, 0xc8, 0x27, 0x34, 0x1f, 0x10, 0x5c, 0x10, 0x42, 0xaa, 0x03, 0x2e, 0xe4, 0x52, 0x87, 0xd6, 0x68, 0x26, 0x00, 0x01, 0x00, 0x26, 0x00, 0xef, 0xbe, 0x12, 0x00, 0x00, 0x00, 0x6e, 0xbb, 0x31, 0x6c, 0x55, 0xd4, 0xda, 0x01, 0x78, 0x92, 0x1f, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0xb8, 0x1b, 0x29, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x14, 0x00, 0x56, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x58, 0x55, 0x62, 0x11, 0x00, 0x54, 0x61, 0x73, 0x6b, 0x42, 0x61, 0x72, 0x00, 0x40, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xec, 0x58, 0x55, 0x62, 0xec, 0x58, 0x55, 0x62, 0x2e, 0x00, 0x00, 0x00, 0x41, 0xb5, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xe1, 0x12, 0x00, 0x54, 0x00, 0x61, 0x00, 0x73, 0x00, 0x6b, 0x00, 0x42, 0x00, 0x61, 0x00, 0x72, 0x00, 0x00, 0x00, 0x16, 0x00, 0x0e, 0x01, 0x32, 0x00, 0x97, 0x01, 0x00, 0x00, 0xa7, 0x54, 0x66, 0x2a, 0x20, 0x00, 0x46, 0x49, 0x4c, 0x45, 0x45, 0x58, 0x7e, 0x31, 0x2e, 0x4c, 0x4e, 0x4b, 0x00, 0x00, 0x7c, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xec, 0x58, 0x55, 0x62, 0xec, 0x58, 0x55, 0x62, 0x2e, 0x00, 0x00, 0x00, 0x8f, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x13, 0xa2, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x20, 0x00, 0x45, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6e, 0x00, 0x6b, 0x00, 0x00, 0x00, 0x40, 0x00, 0x73, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x2c, 0x00, 0x2d, 0x00, 0x32, 0x00, 0x32, 0x00, 0x30, 0x00, 0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x22, 0x00, 0x00, 0x00, 0x1e, 0x00, 0xef, 0xbe, 0x02, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x50, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x64, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x12, 0x00, 0x00, 0x00, 0x2b, 0x00, 0xef, 0xbe, 0x06, 0x7e, 0x2b, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x1c, 0x00, 0x42, 0x00, 0x00, 0x00, 0x1d, 0x00, 0xef, 0xbe, 0x02, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x45, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x9c, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9b, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xcc, 0xc6, 0x67, 0x2e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x43, 0x3a, 0x5c, 0x55, 0x73, 0x65, 0x72, 0x73, 0x5c, 0x6d, 0x71, 0x61, 0x64, 0x64, 0x5c, 0x41, 0x70, 0x70, 0x44, 0x61, 0x74, 0x61, 0x5c, 0x52, 0x6f, 0x61, 0x6d, 0x69, 0x6e, 0x67, 0x5c, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x5c, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x45, 0x78, 0x70, 0x6c, 0x6f, 0x72, 0x65, 0x72, 0x5c, 0x51, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x4c, 0x61, 0x75, 0x6e, 0x63, 0x68, 0x5c, 0x55, 0x73, 0x65, 0x72, 0x20, 0x50, 0x69, 0x6e, 0x6e, 0x65, 0x64, 0x5c, 0x54, 0x61, 0x73, 0x6b, 0x42, 0x61, 0x72, 0x5c, 0x46, 0x69, 0x6c, 0x65, 0x20, 0x45, 0x78, 0x70, 0x6c, 0x6f, 0x72, 0x65, 0x72, 0x2e, 0x6c, 0x6e, 0x6b, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0xa0, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x6b, 0x6f, 0x68, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8a, 0x66, 0xdf, 0x53, 0xed, 0xfe, 0x4d, 0x94, 0xc2, 0x54, 0xa6, 0x7e, 0xf5, 0x91, 0x6f, 0x81, 0xa1, 0xe8, 0x74, 0x48, 0x40, 0xef, 0x11, 0xb4, 0x18, 0xf8, 0xca, 0xb8, 0x09, 0xae, 0xa5, 0x30, 0x8a, 0x66, 0xdf, 0x53, 0xed, 0xfe, 0x4d, 0x94, 0xc2, 0x54, 0xa6, 0x7e, 0xf5, 0x91, 0x6f, 0x81, 0xa1, 0xe8, 0x74, 0x48, 0x40, 0xef, 0x11, 0xb4, 0x18, 0xf8, 0xca, 0xb8, 0x09, 0xae, 0xa5, 0x45, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0xa0, 0x39, 0x00, 0x00, 0x00, 0x31, 0x53, 0x50, 0x53, 0xb1, 0x16, 0x6d, 0x44, 0xad, 0x8d, 0x70, 0x48, 0xa7, 0x48, 0x40, 0x2e, 0xa4, 0x3d, 0x78, 0x8c, 0x1d, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x7f, 0x26, 0x1b, 0x1c, 0xcb, 0x09, 0xb9, 0x43, 0x86, 0x43, 0x2e, 0x11, 0x5b, 0xbb, 0x0d, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            Type = "Binary"
            Path = $regPath1
        },
        @{
            Name = "Favorites"
            Value = [byte[]]@(0x00, 0xa4, 0x01, 0x00, 0x00, 0x3a, 0x00, 0x1f, 0x80, 0xc8, 0x27, 0x34, 0x1f, 0x10, 0x5c, 0x10, 0x42, 0xaa, 0x03, 0x2e, 0xe4, 0x52, 0x87, 0xd6, 0x68, 0x26, 0x00, 0x01, 0x00, 0x26, 0x00, 0xef, 0xbe, 0x12, 0x00, 0x00, 0x00, 0x6e, 0xbb, 0x31, 0x6c, 0x55, 0xd4, 0xda, 0x01, 0x78, 0x92, 0x1f, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0xb8, 0x1b, 0x29, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x14, 0x00, 0x56, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x58, 0x55, 0x62, 0x11, 0x00, 0x54, 0x61, 0x73, 0x6b, 0x42, 0x61, 0x72, 0x00, 0x40, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xec, 0x58, 0x55, 0x62, 0xec, 0x58, 0x55, 0x62, 0x2e, 0x00, 0x00, 0x00, 0x41, 0xb5, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xe1, 0x12, 0x00, 0x54, 0x00, 0x61, 0x00, 0x73, 0x00, 0x6b, 0x00, 0x42, 0x00, 0x61, 0x00, 0x72, 0x00, 0x00, 0x00, 0x16, 0x00, 0x12, 0x01, 0x32, 0x00, 0x97, 0x01, 0x00, 0x00, 0xa7, 0x54, 0x66, 0x2a, 0x20, 0x00, 0x46, 0x49, 0x4c, 0x45, 0x45, 0x58, 0x7e, 0x31, 0x2e, 0x4c, 0x4e, 0x4b, 0x00, 0x00, 0x7c, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xec, 0x58, 0x55, 0x62, 0xec, 0x58, 0x55, 0x62, 0x2e, 0x00, 0x00, 0x00, 0x8f, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x13, 0xa2, 0x00, 0x46, 0x00, 0x69, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x20, 0x00, 0x45, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x6c, 0x00, 0x6e, 0x00, 0x6b, 0x00, 0x00, 0x00, 0x40, 0x00, 0x73, 0x00, 0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x2c, 0x00, 0x2d, 0x00, 0x32, 0x00, 0x32, 0x00, 0x30, 0x00, 0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x12, 0x00, 0x00, 0x00, 0x2b, 0x00, 0xef, 0xbe, 0x06, 0x7e, 0x2b, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x1c, 0x00, 0x42, 0x00, 0x00, 0x00, 0x1d, 0x00, 0xef, 0xbe, 0x02, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00, 0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x74, 0x00, 0x2e, 0x00, 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x45, 0x00, 0x78, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x6f, 0x00, 0x72, 0x00, 0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x26, 0x00, 0x00, 0x00, 0x1e, 0x00, 0xef, 0xbe, 0x02, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6d, 0x00, 0x50, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x64, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0xff)
            Type = "Binary"
            Path = $regPath1
        },
        @{
            Name = "FavoritesChanges"
            Value = 0x0c
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "FavoritesVersion"
            Value = 0x03
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "MailPin"
            Value = 0x01
            Type = "DWord"
            Path = $regPath2
        },
        @{
            Name = "TFLPin"
            Value = 0x01
            Type = "DWord"
            Path = $regPath2
        }
    )
    Try{
        foreach ($regValue in $regValues) {
            Set-ItemProperty -Path $regValue.Path -Name $regValue.Name -Value $regValue.Value -Type $regValue.Type
        }
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
function Enable-EndTaskTaskbar {
    Write-Host "Enable EndTask Taskbar"
    $Enabled = 1
    $Name = "TaskbarEndTask"
    Try{
        $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"
        # Ensure the registry key exists
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        # Set the property, creating it if it doesn''t exist
        New-ItemProperty -Path $Path -Name $name -PropertyType DWord -Value $Enabled -Force | Out-Null
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
    
}
function Show-IconsSysTray{
    $registryPath = "HKCU:\Control Panel\NotifyIconSettings"
    $subKeys = Get-ChildItem -Path $registryPath
    $Enable = 1
    Write-Host "Show Icons SysTray"
    foreach ($subKey in $subKeys) {
        # Check for specific values in the subkey that might identify "Safely Remove Hardware"
        $values = Get-ItemProperty -Path $subKey.PSPath
        #Write-Host $values
        Write-Host $subKey.PSPath
        $Path = $subKey.PSPath
        $Name = "IsPromoted"
    
        if ($values.IconGuid -eq "{7820AE78-23E3-4229-82C1-E41CB67D5B9C}" -and $values.ExecutablePath -eq "{F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe" ){
            Write-Host "FOUND IT" -ForegroundColor Green
            $Enable = 1
        }
        else{
            $Enable = 0
        }
        Try{
            # Ensure the registry key exists
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -Force | Out-Null
            }
            # Set the property, creating it if it doesn''t exist
            New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Enable -Force | Out-Null
        }
        Catch [System.Security.SecurityException] {
            Write-Warning "Unable to set $Path\$Name to $Enable due to a Security Exception"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Warning $psitem.Exception.ErrorRecord
        }
        Catch{
            Write-Warning "Unable to set $Name due to unhandled exception"
            Write-Warning $psitem.Exception.StackTrace
        }
    }
}
function Set-TimeZone {
    Write-Host "Set Time Zone To Amman Jordan"

    $regPath1 = "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    # Create the registry key if it doesn't exist
    if (!(Test-Path -Path $regPath1)) {
        New-Item -Path $regPath1 -Force | Out-Null
    }
    $regValues = @(
        @{
            Name = "Bias"
            Value = ffffff4c
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "DaylightBias"
            Value = ffffffc4
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "DaylightStart"
            Value = [byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
            Type = "Binary"
            Path = $regPath1
        },
        @{
            Name = "StandardStart"
            Value = [byte[]]@(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
            Type = "Binary"
            Path = $regPath1
        },
        @{
            Name = "StandardBias"
            Value = 00000000
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "DynamicDaylightTimeDisabled"
            Value = 00000000
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "ActiveTimeBias"
            Value = ffffff4c
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "RealTimeIsUniversal"
            Value = 00000001
            Type = "DWord"
            Path = $regPath1
        },
        @{
            Name = "DaylightName"
            Value = "@tzres.dll,-334"
            Type = "String"
            Path = $regPath1
        },
        @{
            Name = "StandardName"
            Value = "@tzres.dll,-335"
            Type = "String"
            Path = $regPath1
        },
        @{
            Name = "TimeZoneKeyName"
            Value = "Jordan Standard Time"
            Type = "String"
            Path = $regPath1
        }
    )
    Try{
        foreach ($regValue in $regValues) {
            # Set the property, creating it if it doesn''t exist
            New-ItemProperty -Path $regValue.Path -Name $regValue.Name -PropertyType $regValue.Type -Value $regValue.Value -Force | Out-Null
        }
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $regPath1\$Name to $Enabled due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}


function Set-Registry {
    <#
    EXAMPLE
    Set-Registry -Name "PublishUserActivities" -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Type "DWord" -Value "0"
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "QWord", "MultiString")]
        [string]$Type,
        
        [string]$Value
    )
    If (!(Test-Path $Path)) {
        Write-Warning "$Path was not found, Creating..."
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    Try{
        Write-Host "Setting registry key: $Name at $Path" -ForegroundColor Cyan
        # Set the property, creating it if it doesn''t exist
        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
    Catch [System.Security.SecurityException] {
        Write-Warning "Unable to set $Path\$Name to $Value due to a Security Exception"
    }
    Catch [System.Management.Automation.ItemNotFoundException] {
        Write-Warning $psitem.Exception.ErrorRecord
    }
    Catch{
        Write-Warning "Unable to set $Name due to unhandled exception"
        Write-Warning $psitem.Exception.StackTrace
    }
}
# To Use "HKU:\" reg path instaed of "Registry::HKU\"
if (!(Test-Path 'HKU:')) { 
    Write-Host "Creating HKU: drive..." -ForegroundColor Yellow
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS 
}
$RegistrySettings = @(
    @{Message = "Display full path in the title bar"
        Data = @(
            @{
                Name = "FullPath"
                Type = "DWord"
                Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState"
                Value = "1"
            }
        )
    }
    @{Message = "Show Drives With No Media"
        Data = @(
            @{
                Name = "HideDrivesWithNoMedia"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Value = "1"
            }
        )
    }
    @{Message = "Show protected operating system files"
        Data = @(
            @{
                Name = "ShowSuperHidden"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Value = "1"
            }
        )
    }
    @{Message = "Use check box to select items"
        Data = @(
            @{
                Name = "AutoCheckSelect"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Value = "1"
            }
        )
    }
    @{Message = "Show pin menu icon when pen in use"
        Data = @(
            @{
                Name = "PenWorkspaceButtonDesiredVisibility"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace"
                Value = "1"
            }
        )
    }
    @{Message = "Show touch keyboard icon"
        Data = @(
            @{
                Name = "TipbandDesiredVisibility"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7"
                Value = "1"
            }
        )
    }
    @{Message = "Set Start Layout to More pin"
        Data = @(
            @{
                Name = "Start_Layout"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                Value = "1"
            }
        )
    }
    @{Message = "Show most used Apps"
        Data = @(
            @{
                Name = "ShowFrequentList"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start"
                Value = "1"
            }
        )
    }
    @{Message = "Show settings, Downloads, Pictures ... icon start menu"
        Data = @(
            @{
                Name = "VisiblePlaces"
                Type = "Binary"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start"
                Value = [byte[]]@(0xbc ,0x24 ,0x8a ,0x14 ,0x0c ,0xd6 ,0x89 ,0x42 ,0xa0 ,0x80 ,0x6e ,0xd9 ,0xbb ,0xa2 ,0x48 ,0x82 ,0xce ,0xd5 ,0x34 ,0x2d ,0x5a ,0xfa ,0x43 ,0x45 ,0x82 ,0xf2 ,0x22 ,0xe6 ,0xea ,0xf7 ,0x77 ,0x3c ,0x2f ,0xb3 ,0x67 ,0xe3 ,0xde ,0x89 ,0x55 ,0x43 ,0xbf ,0xce ,0x61 ,0xf3 ,0x7b ,0x18 ,0xa9 ,0x37 ,0xa0 ,0x07 ,0x3f ,0x38 ,0x0a ,0xe8 ,0x80 ,0x4c ,0xb0 ,0x5a ,0x86 ,0xdb ,0x84 ,0x5d ,0xbc ,0x4d ,0xc5 ,0xa5 ,0xb3 ,0x42 ,0x86 ,0x7d ,0xf4 ,0x42 ,0x80 ,0xa4 ,0x93 ,0xfa ,0xca ,0x7a ,0x88 ,0xb5 ,0x86 ,0x08 ,0x73 ,0x52 ,0xaa ,0x51 ,0x43 ,0x42 ,0x9f ,0x7b ,0x27 ,0x76 ,0x58 ,0x46 ,0x59 ,0xd4 ,0x44 ,0x81 ,0x75 ,0xfe ,0x0d ,0x08 ,0xae ,0x42 ,0x8b ,0xda ,0x34 ,0xed ,0x97 ,0xb6 ,0x63 ,0x94)
            }
        )
    }
    @{Message = "Enable Clipboard History 🪟+v"
        Data = @(
            @{
                Name = "EnableClipboardHistory"
                Type = "DWord"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Clipboard"
                Value = "1"
            }
        )
    }
    @{Message = "Set autoplay to take no action"
        Data = @(
            @{
                Name = "(Default)"
                Type = "String"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival"
                Value = "MSTakeNoAction"
            }
            @{
                Name = "(Default)"
                Type = "String"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival"
                Value = "MSTakeNoAction"
            }
            @{
                Name = "(Default)"
                Type = "String"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate\ShowPicturesOnArrival"
                Value = "MSTakeNoAction"
            }
            @{
                Name = "(Default)"
                Type = "String"
                Path = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival"
                Value = "MSTakeNoAction"
            }
        )
    }
)


foreach($Setting in $RegistrySettings){
    Write-Host $Setting.Message -ForegroundColor Green
    foreach($Entry in $Setting.Data){
        Set-Registry -Name $Entry.Name -Path $Entry.Path -Type $Entry.Type -Value $Entry.Value
    }
}








Enable-DarkMode
Enable-BingSearch
Disable-SearchBoxTaskBar
Enable-HiddenFiles
Enable-HideFileExt
Enable-TaskbarAlignment
Disable-TaskbarWidgets
Enable-TaskView
Enable-UltimatePerformance
Disable-DeliveryOptimization
Set-TaskbarIcons
Enable-EndTaskTaskbar
Show-IconsSysTray
Set-TimeZone
