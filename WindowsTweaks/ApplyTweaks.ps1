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
    $Enabled = 1
    Try{
        $Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
        If (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
        Set-ItemProperty -Path $Path -Name "DODownloadMode" -Type DWord -Value $Enabled
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
            Value = [byte[]]@(0x33, 0x03, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x83, 0x00, 0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x18, 0x57, 0x24, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x59, 0xe0, 0x2d, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x5c, 0xf4, 0xe1, 0xfb, 0xd1, 0x61, 0xd8, 0x01, 0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x3a, 0x00, 0x1f, 0x80, 0xc8, 0x27, 0x34, 0x1f, 0x10, 0x5c, 0x10, 0x42, 0xaa, 0x03, 0x2e, 0xe4, 0x52, 0x87, 0xd6, 0x68, 0x26, 0x00, 0x01, 0x00, 0x26, 0x00, 0xef, 0xbe, 0x12, 0x00, 0x00, 0x00, 0x6e, 0xbb, 0x31, 0x6c, 0x55, 0xd4, 0xda, 0x01, 0x78, 0x92, 0x1f, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0xb8, 0x1b, 0x29, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x14, 0x00, 0x56, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x58, 0x55, 0x62, 0x11, 0x00, 0x54, 0x61, 0x73, 0x6b, 0x42, 0x61, 0x72, 0x00, 0x40, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xec, 0x58, 0x55, 0x62, 0xec, 0x58, 0x55, 0x62, 0x2e, 0x00, 0x00, 0x00)
            Type = "Binary"
            Path = $regPath1
        },
        @{
            Name = "Favorites"
            Value = [byte[]]@(0x33, 0x03, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x83, 0x00, 0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x18, 0x57, 0x24, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x59, 0xe0, 0x2d, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x5c, 0xf4, 0xe1, 0xfb, 0xd1, 0x61, 0xd8, 0x01, 0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x3a, 0x00, 0x1f, 0x80, 0xc8, 0x27, 0x34, 0x1f, 0x10, 0x5c, 0x10, 0x42, 0xaa, 0x03, 0x2e, 0xe4, 0x52, 0x87, 0xd6, 0x68, 0x26, 0x00, 0x01, 0x00, 0x26, 0x00, 0xef, 0xbe, 0x12, 0x00, 0x00, 0x00, 0x6e, 0xbb, 0x31, 0x6c, 0x55, 0xd4, 0xda, 0x01, 0x78, 0x92, 0x1f, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0xb8, 0x1b, 0x29, 0xa2, 0x55, 0xd4, 0xda, 0x01, 0x14, 0x00, 0x56, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0x58, 0x55, 0x62, 0x11, 0x00, 0x54, 0x61, 0x73, 0x6b, 0x42, 0x61, 0x72, 0x00, 0x40, 0x00, 0x09, 0x00, 0x04, 0x00, 0xef, 0xbe, 0xec, 0x58, 0x55, 0x62, 0xec, 0x58, 0x55, 0x62, 0x2e, 0x00, 0x00, 0x00)
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
        # Set the registry values
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

